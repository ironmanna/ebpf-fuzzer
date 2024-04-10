import random
import pprint
import subprocess
import sys
import os
import time
import cLoaderProg
import timeit
import threading

from threading import Thread
from threading import Condition

from timeit import default_timer as timer
from datetime import timedelta

from eBPFGenerator import eBPFGenerator

THREAD_COUNT=10
PRINT_DEBUG=0
MAX_RUN_COUNT = 5
elapsed_time=0;
prof_merge_lock = threading.Lock()
STOP_FUZZER = False

def triage_failure(verifier_out):
    file1 = open("verifier_error.txt", "a")  # append mode
    file1.write("===Triage=====\n")
    file1.write(verifier_out[len(verifier_out)-5])
    file1.write("\n")
    file1.close()

def random_bpf_insn_all_class():

    random_insn_list = []

    random_insn_list = gen_alu_insn(random_insn_list)
    random_insn_list = gen_mov_insn(random_insn_list)
    random_insn_list = gen_ld_insn(random_insn_list) 
    random_insn_list = gen_st_insn(random_insn_list)
    random_insn_list = gen_jmp_insn(random_insn_list)
    random_insn_list = gen_exit_insn(random_insn_list)

    random_insn_list = fix_unintialized(random_insn_list) 
    if PRINT_DEBUG:
        pprint.pprint(random_insn_list)
     
    return print_bpf_insn_to_str(random_insn_list)

def check_verification_status(out):

    global assert_error 
    st = True
    output_lines = out.split("\n")
    for index,line in enumerate(output_lines) :
        if "BPF Verification Failed" in line:
            st = False
            triage_failure(output_lines[index:])
        if "ASSERT_ERROR" in  line:
            print("===============ALU_ERROR=============")
            assert_error  += 1 
    return st

def run_single_ebpf_prog():

    global FUZZER_ST_VER_PASS
    global FUZZER_ST_VER_FAIL
    global elapsed_time

    ebpf_gen = eBPFGenerator()
    random_str = ebpf_gen.generate_instructions(random.randint(2,200) )#to do max_size
    print(random_str)
    c_contents  = cLoaderProg.LOADER_PROG_HEAD + random_str + cLoaderProg.LOADER_PROG_TAIL

    filename = "out_" + hex(random.randint(0xffffff, 0xfffffffffff))[2:]
    f = open(filename+".c","w")
    f.write(c_contents)
    f.close()


    os.sync()
    build_cmd = "bash ./build.sh " + filename
    build_out = subprocess.run(build_cmd.split(' '))

    #my_env
    my_env = os.environ.copy()
    my_env["LLVM_PROFILE_FILE"] =   filename +  ".profraw"
    # Execute
    exec_cmd =  "./" + filename
    ebpf_out = subprocess.run(exec_cmd.split(' '),stdout=subprocess.PIPE,env=my_env)

    ebpf_out = ebpf_out.stdout.decode("utf-8")

    if(check_verification_status(ebpf_out)):
        FUZZER_ST_VER_PASS +=1
    else:
        FUZZER_ST_VER_FAIL +=1

    # prof_merge_cmd= "bash ./gen_cov.sh " + filename
    # prof_merge_lock.acquire()
    # prof_merge_out = subprocess.run(prof_merge_cmd.split(' '))
    # prof_merge_lock.release()

    # Mkdir command
    mkdir_cmd = "mkdir -p tmp/" + filename
    mkdir_out = subprocess.run(mkdir_cmd.split(' '))
    # Kcov command
    kcov_cmd = "kcov tmp/" + filename + "/ ./" + filename + " > /dev/null 2>&1"
    kcov_out = subprocess.run(kcov_cmd, shell=True)
    # Kcov merge
    kcov_merge_cmd = "kcov --merge tmp/merged_cov/ tmp/" + filename + "/"
    kcov_merge_out = subprocess.run(kcov_merge_cmd.split(' '))
    # Kcov remove
    # kcov_remove_cmd = "rm -rf tmp/" + filename
    # kcov_remove_out = subprocess.run(kcov_remove_cmd.split(' '))
    

    '''
    if os.path.exists(filename + ".o"):
        os.remove(filename + ".o")
    if os.path.exists(filename + "-in.o"):
        os.remove(filename + "-in.o")
    if os.path.exists(filename + ".c"):
        os.remove(filename + ".c")
    if os.path.exists(filename):
        os.remove(filename)
    if os.path.exists(filename + ".profraw"):
        os.remove(filename  + ".profraw" )
    '''

def _run_single_ebpf_prog():
    
    global FUZZER_ST_VER_PASS 
    global FUZZER_ST_VER_FAIL

    ebpf_gen = eBPFGenerator()
    random_str = ebpf_gen.generate_instructions(random.randint(2,200) )#to do max_size 
    c_contents  = cLoaderProg.LOADER_PROG_HEAD + random_str + cLoaderProg.LOADER_PROG_TAIL

    filename = "out_" + hex(random.randint(0xffffff, 0xfffffffffff))[2:]
    f = open(filename+".c","w")
    f.write(c_contents)
    f.close()

    os.sync() 
    build_cmd = "bash ./build_small.sh " + filename 
    build_out = subprocess.run(build_cmd.split(' '))

    # Execute 
    exec_cmd = "./" + filename
    ebpf_out = subprocess.run(exec_cmd.split(' '),stdout=subprocess.PIPE)

    ebpf_out = ebpf_out.stdout.decode("utf-8")

    if(check_verification_status(ebpf_out)):
        FUZZER_ST_VER_PASS +=1
    else:
        FUZZER_ST_VER_FAIL +=1

    if os.path.exists(filename + ".o"):
        os.remove(filename + ".o")
    if os.path.exists(filename + "-in.o"):
        os.remove(filename + "-in.o")
    if os.path.exists(filename + ".c"):
        os.remove(filename + ".c")
    if os.path.exists(filename):
        os.remove(filename)


def fuzzer_task(inp):

    while STOP_FUZZER !=  True:
        run_single_ebpf_prog()


# Main
##########################################################
##########################################################

use_last_code = False
if len(sys.argv) == 2:
    if sys.argv[1] ==  "--use-last":
        use_last_code = True;

FUZZER_ST_VER_PASS = 0
FUZZER_ST_VER_FAIL = 0

threads = [Thread(target=fuzzer_task   , args=(x,))  for x in range(0,THREAD_COUNT)]

t = time.time()
t_0 = timeit.default_timer()

for thread in threads:
    thread.start()

last_print = -1

assert_error = 0
while True:
    time.sleep(1)  
    t_1 = timeit.default_timer()
    elapsed_time = round((t_1 - t_0) * 1, 3)

    total_run = FUZZER_ST_VER_FAIL + FUZZER_ST_VER_PASS 
    if elapsed_time == 0:
        elapsed_time = 1
    speed = round(total_run*1.0/(elapsed_time),1)

    
    elapsed_time = round(elapsed_time,0)
    if(elapsed_time % 5 == 0):
        # prof_merge_cmd= "bash ./print_cov.sh "   + str(elapsed_time)
        # prof_merge_lock.acquire()
        # prof_merge_out = subprocess.run(prof_merge_cmd.split(' '))
        # prof_merge_lock.release()
        print("Elapsed time: " + str(elapsed_time))


    if total_run > MAX_RUN_COUNT:
        STOP_FUZZER = True
        break 
    
for thread in threads:
    thread.join()
