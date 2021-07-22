#!/usr/bin/env python
# coding=utf-8
import argparse
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import json
import pathlib,zipfile

from androguard.core import androconf
from androguard.core.analysis import analysis
from androguard.core.androconf import show_logging
from androguard.core.bytecodes import apk, dvm
from androguard.util import read
from dex2c.compiler import Dex2C
from dex2c.util import JniLongName, get_method_triple, get_access_method, is_synthetic_method, is_native_method,MangleForJni,EscForJni

APKTOOL = 'tools/apktool.jar'
NDKBUILD = 'ndk-build'
LIBNATIVECODE = 'libnc.so'
UPX = ''
SEVENZIP=''

logger = logging.getLogger('dcc')

tempfiles = []

def is_windows():
    return os.name == 'nt'

def cpu_count():
    num_processes = os.cpu_count()
    if num_processes is None:
        num_processes = 2
    return num_processes

def make_temp_dir(prefix='dcc'):
    global tempfiles
    tmp = tempfile.mkdtemp(prefix=prefix,dir='./temp')
    tempfiles.append(tmp)
    return tmp


def make_temp_file(suffix='',prefix='dcc'):
    global tempfiles
    fd, tmp = tempfile.mkstemp(suffix=suffix,prefix=prefix,dir='./temp')
    os.close(fd)
    tempfiles.append(tmp)
    return tmp


def clean_temp_files():
    logger.info("debug mode do not clean temp files")
    return
    for name in tempfiles:
        if not os.path.exists(name):
            continue
        logger.info('removing %s' % name)
        if os.path.isdir(name):
            shutil.rmtree(name)
        else:
            os.unlink(name)


class ApkTool(object):
    @staticmethod
    def decompile(apk):
        outdir = make_temp_dir('dcc-apktool-')
        if os.path.exists(outdir):
            shutil.rmtree(outdir)
        subprocess.check_call(['java', '-jar', APKTOOL, 'd', '-r', '-o', outdir, apk])
        return outdir
    # @staticmethod
    # def replace_zip(src_dir,in_zip_path,out_zip_path):
    #     src_dir=src_dir.replace('\\','/')
    #     entry_map=dict()
    #     for root, dirs, files in os.walk(src_dir, topdown=False):
    #         for f in files:
    #             p=os.path.join(root,f).replace('\\','/')
    #             entry_name=p.replace(src_dir,'')
    #             if entry_name.startswith('/'):
    #                 entry_name=entry_name[1:]
    #             entry_map[entry_name]=p

    #     with zipfile.ZipFile(in_zip_path) as inzip, zipfile.ZipFile(out_zip_path, "w",compression=zipfile.ZIP_STORED,compresslevel=9) as outzip:
    #         for inzipinfo in inzip.infolist():
    #             if(inzipinfo.filename.startswith('META-INF')):
    #                 print(f'fff==={inzipinfo.filename}')
    #             with inzip.open(inzipinfo) as infile:
    #                 content = infile.read()
    #                 if inzipinfo.filename in entry_map:
    #                     with open(entry_map[inzipinfo.filename],'rb') as fp:
    #                         logger.info(f'replace zip entry {inzipinfo.filename}')
    #                         content=fp.read()
    #                         del entry_map[inzipinfo.filename]
    #                 outzip.writestr(inzipinfo.filename, content)
    #         for entry_name,p in entry_map.items():
    #             logger.info(f'add zip entry {entry_name}')
    #             with open(p,'rb') as fp:
    #                 outzip.writestr(entry_name,fp.read())
    @staticmethod
    def compile(decompiled_dir,original_apk):
        unsiged_apk = make_temp_file('-unsigned.apk')
        subprocess.check_call(['java', '-jar', APKTOOL, 'b', '-o', unsiged_apk, decompiled_dir])
        # wkdir=os.path.join(decompiled_dir,'build/apk')
        # for file_name in os.listdir(wkdir):
        #     if file_name.endswith('.dex'):
        #         pass
        #     elif file_name=='lib':
        #         pass
        #     else:
        #         rm_file=os.path.join(wkdir,file_name)
        #         if os.path.isfile(rm_file):
        #             os.unlink(rm_file)
        #         else:
        #             shutil.rmtree(rm_file)
        # out_apk=make_temp_file('-build.apk')
        # shutil.copyfile(original_apk,out_apk)
        # ApkTool.replace_zip(wkdir,original_apk,out_apk)
        # return out_apk
        # subprocess.check_call([SEVENZIP,'a','-tzip',out_apk,wkdir,'-mx9'])
        return unsiged_apk


def sign(unsigned_apk, signed_apk):
    pem = os.path.join('tests/testkey/testkey.x509.pem')
    pk8 = os.path.join('tests/testkey/testkey.pk8')
    logger.info("signing %s -> %s" % (unsigned_apk, signed_apk))
    subprocess.check_call(['tools/zipalign.exe','-p', '-f' ,'-v' ,'4',unsigned_apk,signed_apk],stdout=subprocess.DEVNULL)
    subprocess.check_call(['tools/zipalign.exe','-c' ,'-v' ,'4',signed_apk],stdout=subprocess.DEVNULL)
    subprocess.check_call(['java', '-jar', 'tools/apksigner.jar','sign',
    '--key',pk8,
     '--cert',pem , 
     '--v3-signing-enabled', 'false', '--v4-signing-enabled' ,'false',signed_apk])
    subprocess.check_call(['java', '-jar', 'tools/apksigner.jar','verify' ,'-v',signed_apk])


def build_project(project_dir, num_processes=0):
    subprocess.check_call([NDKBUILD, '-j%d' % cpu_count(), '-C', project_dir])


def auto_vm(filename):
    ret = androconf.is_android(filename)
    if ret == 'APK':
        return dvm.DalvikVMFormat(apk.APK(filename).get_dex())
    elif ret == 'DEX':
        return dvm.DalvikVMFormat(read(filename))
    elif ret == 'DEY':
        return dvm.DalvikOdexVMFormat(read(filename))
    raise Exception("unsupported file %s" % filename)


class MethodFilter(object):
    def __init__(self, configure, vm):
        self._compile_filters = []
        self._keep_filters = []
        self._compile_full_match = set()

        self.conflict_methods = set()
        self.native_methods = set()
        self.annotated_methods = set()

        self._load_filter_configure(configure)
        self._init_conflict_methods(vm)
        self._init_native_methods(vm)
        self._init_annotation_methods(vm)

    def _load_filter_configure(self, configure):
        if not os.path.exists(configure):
            return

        with open(configure) as fp:
            for line in fp:
                line = line.strip()
                if not line or line[0] == '#':
                    continue

                if line[0] == '!':
                    line = line[1:].strip()
                    self._keep_filters.append(re.compile(line))
                elif line[0] == '=':
                    line = line[1:].strip()
                    self._compile_full_match.add(line)
                else:
                    self._compile_filters.append(re.compile(line))

    def _init_conflict_methods(self, vm):
        all_methods = {}
        for m in vm.get_methods():
            method_triple = get_method_triple(m, return_type=False)
            if method_triple in all_methods:
                self.conflict_methods.add(m)
                self.conflict_methods.add(all_methods[method_triple])
            else:
                all_methods[method_triple] = m

    def _init_native_methods(self, vm):
        for m in vm.get_methods():
            cls_name, name, _ = get_method_triple(m)

            access = get_access_method(m.get_access_flags())
            if 'native' in access:
                self.native_methods.add((cls_name, name))

    def _add_annotation_method(self, method):
        if not is_synthetic_method(method) and not is_native_method(method):
            self.annotated_methods.add(method)

    def _init_annotation_methods(self, vm):
        for c in vm.get_classes():
            adi_off = c.get_annotations_off()
            if adi_off == 0:
                continue

            adi = vm.CM.get_obj_by_offset(adi_off)
            annotated_class = False
            # ref:https://github.com/androguard/androguard/issues/175
            if adi.get_class_annotations_off() != 0:
                ann_set_item = vm.CM.get_obj_by_offset(adi.get_class_annotations_off())
                for aoffitem in ann_set_item.get_annotation_off_item():
                    annotation_item = vm.CM.get_obj_by_offset(aoffitem.get_annotation_off())
                    encoded_annotation = annotation_item.get_annotation()
                    type_desc = vm.CM.get_type(encoded_annotation.get_type_idx())
                    if type_desc.endswith('Dex2C;'):
                        annotated_class = True
                        for method in c.get_methods():
                            self._add_annotation_method(method)
                        break

            if not annotated_class:
                for mi in adi.get_method_annotations():
                    method = vm.get_method_by_idx(mi.get_method_idx())
                    ann_set_item = vm.CM.get_obj_by_offset(mi.get_annotations_off())

                    for aoffitem in ann_set_item.get_annotation_off_item():
                        annotation_item = vm.CM.get_obj_by_offset(aoffitem.get_annotation_off())
                        encoded_annotation = annotation_item.get_annotation()
                        type_desc = vm.CM.get_type(encoded_annotation.get_type_idx())
                        if type_desc.endswith('Dex2C;'):
                            self._add_annotation_method(method)

    def should_compile(self, method):
        # don't compile functions that have same parameter but differ return type
        if method in self.conflict_methods:
            return False

        # synthetic method
        if is_synthetic_method(method) or is_native_method(method):
            return False

        method_triple = get_method_triple(method)
        cls_name, name, _ = method_triple

        # Android VM may find the wrong method using short jni name
        # don't compile function if there is a same named native method
        if (cls_name, name) in self.native_methods:
            return False

        full_name = ''.join(method_triple)
        for rule in self._keep_filters:
            if rule.search(full_name):
                return False

        if full_name in self._compile_full_match:
            return True

        if method in self.annotated_methods:
            return True

        for rule in self._compile_filters:
            if rule.search(full_name):
                return True

        return False


def copy_compiled_libs(project_dir, decompiled_dir):
    compiled_libs_dir = os.path.join(project_dir, "libs")
    decompiled_libs_dir = os.path.join(decompiled_dir, "lib")
    if not os.path.exists(compiled_libs_dir):
        return
    if not os.path.exists(decompiled_libs_dir):
        shutil.copytree(compiled_libs_dir, decompiled_libs_dir)
        return

    for abi in os.listdir(decompiled_libs_dir):
        dst = os.path.join(decompiled_libs_dir, abi)
        src = os.path.join(compiled_libs_dir, abi)
        if not os.path.exists(src) and abi == 'armeabi':
            src = os.path.join(compiled_libs_dir, 'armeabi-v7a')
            logger.warning('Use armeabi-v7a for armeabi')

        if not os.path.exists(src):
            raise Exception("ABI %s is not supported!" % abi)

        libnc = os.path.join(src, LIBNATIVECODE)
        shutil.copy(libnc, dst)

def compress_native_libs(decompiled_dir):
    if not os.path.exists(UPX):
        logger.warning("UPX NOT SET")
        return
    decompiled_libs_dir = os.path.join(decompiled_dir, "lib")
    my_ndk=pathlib.Path(NDKBUILD).parent.absolute()
    print(f'my_ndk={my_ndk} {type(my_ndk)}')
    stripMap={
                    "armeabi-v7a":os.path.join( my_ndk , 'toolchains/arm-linux-androideabi-4.9/prebuilt/windows-x86_64/bin/arm-linux-androideabi-strip'),
                    "arm64-v8a"  :os.path.join( my_ndk , 'toolchains/aarch64-linux-android-4.9/prebuilt/windows-x86_64/bin/aarch64-linux-android-strip'),
                    "x86"        :os.path.join(my_ndk , 'toolchains/x86-4.9/prebuilt/windows-x86_64/bin/i686-linux-android-strip'),
                    "x86_64"     :os.path.join(my_ndk, 'toolchains/x86_64-4.9/prebuilt/windows-x86_64/bin/x86_64-linux-android-strip'),
    }
    for k in stripMap.keys():
        if is_windows():
            stripMap[k]=stripMap[k]+'.exe'
    for abi in os.listdir(decompiled_libs_dir):
        assert abi in stripMap,'不支持strip'
        stripprogram=stripMap[abi]
        assert os.path.exists(stripprogram),f'strip不存在:{stripprogram}'
        libPath=os.path.join(decompiled_libs_dir,abi,'libstub.so')
        assert os.path.exists(libPath)
        subprocess.check_call([stripprogram, '--strip-unneeded','-R','.note.gnu.property','-v',libPath])
        subprocess.check_call([UPX,'-9','--android-shlib',libPath])



def native_class_methods(smali_path, compiled_methods):
    def next_line():
        return fp.readline()

    def handle_annotanion():
        while True:
            line = next_line()
            if not line:
                break
            s = line.strip()
            code_lines.append(line)
            if s == '.end annotation':
                break
            else:
                continue
    def skip_annotanion():
        while True:
            line = next_line()
            if not line:
                break
            s = line.strip()
            if s == '.end annotation':
                break

    def handle_method_body():
        while True:
            line = next_line()
            if not line:
                break
            s = line.strip()
            if s == '.end method':
                break
            elif s.startswith('.annotation runtime') and s.find('Dex2C') < 0:
                code_lines.append(line)
                handle_annotanion()
            else:
                continue

    def get_stub_code():
        stubCode=clzIndexMap[class_name]
        stubCode=stubCode^20
        # 进行预处理
        return f'0x{stubCode:x}'
    def handle_static_init():
        while True:
            line = next_line()
            if not line:
                break
            s = line.strip()
            # 矫正寄存器数量
            if s.startswith('.locals'):
                if s.split(' ')[-1]=='0':
                    line='    .locals 1\n'
                code_lines.append(line)
                line='\n'
                assert class_name in clzIndexMap,f'找不到:{class_name}'
                code_lines.append(f'const v0, {get_stub_code()}\n')
                code_lines.append('invoke-static {v0}, Lcom/wolf/protect/EntryPoint;->stub(I)V\n')
            code_lines.append(line)
            if s == '.end method':
                break




    code_lines = []
    class_name = ''
    has_static_init=False
    with open(smali_path, 'r') as fp:
        while True:
            line = next_line()
            if not line:
                break
            code_lines.append(line)
            line = line.strip()
            if line.startswith('.class'):
                class_name = line.split(' ')[-1]
            elif re.match(r'\.method.*constructor <clinit>\(\)V',line,re.S):
                handle_static_init()
                has_static_init=True
            elif line.startswith('.method'):
                current_method = line.split(' ')[-1]
                param = current_method.find('(')
                name, proto = current_method[:param], current_method[param:]
                if (class_name, name, proto) in compiled_methods:
                    if line.find(' native ') < 0:
                        code_lines[-1] = code_lines[-1].replace(current_method, 'native ' + current_method)
                    handle_method_body()
                    code_lines.append('.end method\n')
            elif line.startswith('.annotation runtime'):
                if re.match(r'\.annotation.*Dex2C;',line,re.S):
                    del code_lines[-1]
                    skip_annotanion()


    if not has_static_init:
        assert class_name in clzIndexMap,f'找不到:{class_name}'
        code_lines.append('.method public static constructor <clinit>()V\n')
        code_lines.append('    .locals 1\n')
        code_lines.append(f'    const v0, {get_stub_code()}\n')
        code_lines.append('    invoke-static {v0}, Lcom/wolf/protect/EntryPoint;->stub(I)V\n')
        code_lines.append('    return-void\n')
        code_lines.append('.end method\n')
    with open(smali_path, 'w') as fp:
        fp.writelines(code_lines)


def native_compiled_dexes(decompiled_dir, compiled_methods):
    # smali smali_classes2 smali_classes3 ...
    classes_output = list(filter(lambda x: x.find('smali') >= 0, os.listdir(decompiled_dir)))
    todo = []
    for classes in classes_output:
        for root, dirs, files in os.walk(os.path.join(decompiled_dir, classes)):
            for name in files:
                if(name.endswith('Dex2C.smali')):
                    os.unlink(os.path.join(root,name))
        for method_triple in compiled_methods.keys():
            cls_name, name, proto = method_triple
            cls_name = cls_name[1:-1]  # strip L;
            smali_path = os.path.join(decompiled_dir, classes, cls_name) + '.smali'
            if os.path.exists(smali_path):
                todo.append(smali_path)

    for smali_path in todo:
        native_class_methods(smali_path, compiled_methods)

patternFunc = re.compile(r'JNICALL[^{]+')
patternJava = re.compile(r'Java_[^()]+')
# className index
clzIndexMap=dict()
def write_compiled_methods(project_dir, compiled_methods):
    source_dir = os.path.join(project_dir, 'jni', 'nc')
    if not os.path.exists(source_dir):
        os.makedirs(source_dir)


    for method_triple, code in compiled_methods.items():
        full_name = JniLongName(*method_triple)
        filepath = os.path.join(source_dir, full_name) + '.cpp'
        if os.path.exists(filepath):
            logger.warning("Overwrite file %s %s" % (filepath, method_triple))

        with open(filepath, 'w') as fp:
            fp.write('#include "Dex2C.h"\n' + code)

    with open(os.path.join(source_dir, 'compiled_methods.txt'), 'w') as fp:
        fp.write('\n'.join(list(map(''.join, compiled_methods.keys()))))
    
    
    clzMap=dict()
    for method_triple, code in compiled_methods.items():
        if not method_triple[0] in clzMap:
            clzMap[method_triple[0]]=[] 
        clzMap[method_triple[0]].append((method_triple, code))

    funcdeclare=''
    entryArray=f'static const ClassEntry entryArray[] = {{\n'
    clzCodess=''
    index=0
    for clzname, methods in clzMap.items():
        assert clzname[0] == 'L'
        assert clzname[-1] == ';'
        clzMethodArrayName='Jni_'+MangleForJni(clzname[1:-1])
        clzCode=f'static const JNINativeMethod {clzMethodArrayName}[] = {{\n'
        for method_triple, code in methods:
            funcdeclare+='extern '+re.findall(patternFunc, code)[0]+';\n'
            funcName=re.findall(patternJava, code)[0]
            clzCode+=f'{{"{EscForJni(method_triple[1])}", "{EscForJni(method_triple[2])}", reinterpret_cast<void *>({funcName})}},\n'
        clzCode+='};\n'
        findClzName=EscForJni(clzname[1:-1])
        clzIndexMap[clzname]=index
        entryArray+=f'/*index:{index}*/{{"{findClzName}", {clzMethodArrayName}, sizeof({clzMethodArrayName}) / sizeof(JNINativeMethod)}},\n'
        index+=1
        clzCodess+=clzCode
    entryArray+='};\n'

    stubCodes='//CODE BEGIN\n'+funcdeclare+clzCodess+entryArray+'\n//CODE END\n'
    with open(os.path.join(source_dir, 'NativeEntry.cpp'), 'r') as fp:
        stubCodes=fp.read().replace(r'//####REPLACE####',stubCodes)
    with open(os.path.join(source_dir, 'NativeEntry.cpp'), 'w+') as fp:
        fp.write(stubCodes)


def archive_compiled_code(project_dir):
    outfile = make_temp_file('-dcc')
    outfile = shutil.make_archive(outfile, 'zip', project_dir)
    return outfile


def compile_dex(apkfile, filtercfg):
    show_logging(level=logging.INFO)

    d = auto_vm(apkfile)
    dx = analysis.Analysis(d)

    method_filter = MethodFilter(filtercfg, d)

    compiler = Dex2C(d, dx)

    compiled_method_code = {}
    errors = []

    for m in d.get_methods():
        method_triple = get_method_triple(m)

        jni_longname = JniLongName(*method_triple)
        full_name = ''.join(method_triple)

        if method_filter.should_compile(m):
            if len(jni_longname) > 220:
                logger.error("name to long %s(> 220) %s" % (jni_longname, full_name))
                continue
            logger.debug("compiling %s" % (full_name))
            try:
                code = compiler.get_source_method(m)
            except Exception as e:
                logger.warning("compile method failed:%s (%s)" % (full_name, str(e)), exc_info=True)
                errors.append('%s:%s' % (full_name, str(e)))
                continue

            if code:
                compiled_method_code[method_triple] = code

    return compiled_method_code, errors

def is_apk(name):
    return name.endswith('.apk')

def dcc_main(apkfile, filtercfg, outapk, do_compile=True, project_dir=None, source_archive='project-source.zip'):
    if not os.path.exists(apkfile):
        logger.error("file %s is not exists", apkfile)
        return

    compiled_methods, errors = compile_dex(apkfile, filtercfg)

    if errors:
        logger.warning('================================')
        logger.warning('\n'.join(errors))
        logger.warning('================================')

    if len(compiled_methods) == 0:
        logger.info("no compiled methods")
        return

    if project_dir:
        if not os.path.exists(project_dir):
            shutil.copytree('project', project_dir)
        write_compiled_methods(project_dir, compiled_methods)
    else:
        project_dir = make_temp_dir('dcc-project-')
        shutil.rmtree(project_dir)
        shutil.copytree('project', project_dir)
        write_compiled_methods(project_dir, compiled_methods)
        src_zip = archive_compiled_code(project_dir)
        shutil.move(src_zip, source_archive)

    if do_compile:
        build_project(project_dir)

    if is_apk(apkfile) and outapk:
        decompiled_dir = ApkTool.decompile(apkfile)
        native_compiled_dexes(decompiled_dir, compiled_methods)
        shutil.copytree('smali', decompiled_dir+'/smali',dirs_exist_ok=True)
        copy_compiled_libs(project_dir, decompiled_dir)
        compress_native_libs(decompiled_dir)
        unsigned_apk = ApkTool.compile(decompiled_dir,apkfile)
        sign(unsigned_apk, outapk)


sys.setrecursionlimit(5000)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('infile', help='Input APK,DEX name')
    parser.add_argument('-o', '--out', nargs='?', help='Output APK file name')
    parser.add_argument('--sign', action='store_true', default=False, help='Sign apk')
    parser.add_argument('--filter', default='filter.txt', help='Method filter configure file')
    parser.add_argument('--no-build', action='store_true', default=False, help='Do not build the compiled code')
    parser.add_argument('--source-dir', help='The compiled cpp code output directory.')
    parser.add_argument('--project-archive', default='project-source.zip', help='Archive the project directory')

    args = vars(parser.parse_args())
    infile = args['infile']
    outapk = args['out']
    do_sign = args['sign']
    filtercfg = args['filter']
    do_compile = not args['no_build']
    source_archive = args['project_archive']

    if args['source_dir']:
        project_dir = args['source_dir']
    else:
        project_dir = None

    dcc_cfg = {}
    with open('dcc.cfg') as fp:
        dcc_cfg = json.load(fp)

    if 'ndk_dir' in dcc_cfg and os.path.exists(dcc_cfg['ndk_dir']):
        ndk_dir = dcc_cfg['ndk_dir']
        if is_windows():
            NDKBUILD = os.path.join(ndk_dir, 'ndk-build.cmd')
        else:
            NDKBUILD = os.path.join(ndk_dir, 'ndk-build')
    if 'upx_full_path' in dcc_cfg and os.path.exists(dcc_cfg['upx_full_path']):
        UPX = dcc_cfg['upx_full_path']

    if 'apktool' in dcc_cfg and os.path.exists(dcc_cfg['apktool']):
        APKTOOL = dcc_cfg['apktool']
    # if '7z_full_path' in dcc_cfg and os.path.exists(dcc_cfg['7z_full_path']):
    #     SEVENZIP = dcc_cfg['7z_full_path']
    
    # assert len(SEVENZIP)>0 and os.path.exists(SEVENZIP),'请指定7zip全路径'

    try:
        dcc_main(infile, filtercfg, outapk, do_compile, project_dir, source_archive)
    except Exception as e:
        logger.error("Compile %s failed!" % infile, exc_info=True)
    finally:
        clean_temp_files()

