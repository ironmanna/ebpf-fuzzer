#!/usr/bin/env python3

import random
import pprint
import subprocess
import sys
import os
import time
import cLoaderProg
import timeit
import threading
import collections

from threading import Thread
from threading import Condition

from timeit import default_timer as timer
from datetime import timedelta

from eBPFGenerator import eBPFGenerator

THREAD_COUNT= 5
PRINT_DEBUG=0
MAX_RUN_COUNT = 50
elapsed_time=0
prof_merge_lock_1 = threading.Lock()
prof_merge_lock_2 = threading.Lock()
STOP_FUZZER = False
THREAD_PENDULUM = False

baseline_cov = {}

# Create a new deque for the ebpf programs
ebpf_program_deque = collections.deque()

# Create a new deque for the ebpf map sections
ebpf_map_section_deque = collections.deque()

class eBPF_program:
    def __init__(self, instructions):
        self.instructions = instructions

    def getInstructions(self):
        return self.instructions
    
class eBPF_map_section:
    def __init__(self, map_section):
        self.map_section = map_section

    def getMapSection(self):
        return self.map_section

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

def check_for_improvement_in_coverage(filename):
    #for all files in folder Coverage/filename/filename.something check if there is any improvement in coverage
    #the coverage is collected inside a dictionary that maps each name of the file to the percentage of coverage
    #if the file is not in the dictionary, it is added with the coverage percentage
    #if the file is in the dictionary, the coverage percentage is updated if the new percentage is higher
    #the dictionary is saved in a variable named baseline_cov

    coverage_folder = ""
    for root, dirs, files in os.walk("./Coverage/" + filename + "/"):
        for dir in dirs:
            #print("Dir: " + dir)
            if dir.startswith(filename):
                coverage_folder = dir
                print("Coverage folder: " + coverage_folder)
                break
    
    found_something = False
    for files in os.listdir("./Coverage/" + filename + "/" + coverage_folder):
        if files.endswith(".js") and not files.startswith(filename):
            file = open("./Coverage/" + filename + "/" + coverage_folder + "/" + files, "r")
            lines = file.readlines()
            for line in lines:
                #the line is var header = { "command" : "test_array_map", "date" : "2024-04-04 14:19:26", "instrumented" : 10, "covered" : 0,};
                #we need to extract the coverage percentage that is the last number in the line
                if line.startswith("var header"):
                    coverage_percentage = float(line.split()[-1].strip(",};"))
                    #print("Coverage percentage: " + str(coverage_percentage))
                    prof_merge_lock_1.acquire()
                    if files not in baseline_cov:
                        baseline_cov[files] = coverage_percentage
                        #print("New: " + files + " with coverage: " + str(coverage_percentage))
                        found_something = True
                    else:
                        if coverage_percentage > baseline_cov[files]:
                            baseline_cov[files] = coverage_percentage
                            #print("Improved on: " + files + " with coverage: " + str(coverage_percentage))
                            found_something = True
                    prof_merge_lock_1.release()
            file.close()
    return found_something

def run_single_ebpf_prog():

    global FUZZER_ST_VER_PASS
    global FUZZER_ST_VER_FAIL
    global elapsed_time

    ebpf_gen = eBPFGenerator()
    random_str = ebpf_gen.generate_instructions(random.randint(2,200) )#to do max_size
    maps_str = ebpf_gen.generate_maps(random.randint(0,28))
    #print(random_str)
    c_contents  = cLoaderProg.LOADER_PROG_HEAD + random_str + cLoaderProg.LOADER_PROG_MID_SECTION + maps_str + cLoaderProg.LOADER_PROG_TAIL

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
    mkdir_cmd = "mkdir -p Coverage/" + filename
    mkdir_out = subprocess.run(mkdir_cmd.split(' '))
    # Kcov command
    kcov_cmd = "kcov Coverage/" + filename + "/ ./" + filename + " > /dev/null 2>&1"
    kcov_out = subprocess.run(kcov_cmd, shell=True)
    # Kcov merge
    kcov_merge_cmd = "kcov --merge Coverage/merged_cov/ Coverage/" + filename + "/"
    kcov_merge_out = subprocess.run(kcov_merge_cmd.split(' '))

    found_something = check_for_improvement_in_coverage(filename)
    if found_something:
        #print("Found something!")
        ebpf_prog = eBPF_program(random_str)
        ebpf_program_deque.append(ebpf_prog)
        ebpf_map = eBPF_map_section(maps_str)
        ebpf_map_section_deque.append(ebpf_map)
    
    # Kcov remove
    kcov_remove_cmd = "rm -rf Coverage/" + filename
    kcov_remove_out = subprocess.run(kcov_remove_cmd.split(' '))
    
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

def run_heurstic_ebpf_prog( ebpf_instructions : eBPF_program):

    ebpf_gen = eBPFGenerator()
    print("eBPF instructions from deque")
    random_str = ebpf_gen.ask_gpt3_to_generate_ebpf_program(ebpf_instructions.getInstructions())
    print("ChatGPT method ended")
    maps_str = ebpf_gen.generate_maps(random.randint(0,28))
    
    print("eBPF instructions from ChatGPT")
    print(random_str)
    print("------------END------------")

    c_contents  = cLoaderProg.LOADER_PROG_HEAD + random_str + cLoaderProg.LOADER_PROG_MID_SECTION + maps_str + cLoaderProg.LOADER_PROG_TAIL

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
    mkdir_cmd = "mkdir -p Coverage/" + filename
    mkdir_out = subprocess.run(mkdir_cmd.split(' '))
    # Kcov command
    kcov_cmd = "kcov Coverage/" + filename + "/ ./" + filename + " > /dev/null 2>&1"
    kcov_out = subprocess.run(kcov_cmd, shell=True)
    # Kcov merge
    kcov_merge_cmd = "kcov --merge Coverage/merged_cov/ Coverage/" + filename + "/"
    kcov_merge_out = subprocess.run(kcov_merge_cmd.split(' '))

    found_something = check_for_improvement_in_coverage(filename)
    if found_something:
        #print("Found something!")
        ebpf_map = eBPF_map_section(maps_str)
        ebpf_map_section_deque.append(ebpf_map)
        new_ebpf_program = eBPF_program(random_str)
        ebpf_program_deque.append(new_ebpf_program)


    # Kcov remove
    kcov_remove_cmd = "rm -rf Coverage/" + filename
    kcov_remove_out = subprocess.run(kcov_remove_cmd.split(' '))
    
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


def run_heurstic_ebpf_map_prog(ebpf_map_section):

    ebpf_gen = eBPFGenerator()
    random_str = ebpf_gen.generate_instructions(random.randint(2,200) )#to do max_size
    print("Map section from deque")
    maps_str = ebpf_gen.ask_gpt3_to_generate_map_section(ebpf_map_section)
    print("ChatGPT method ended")
    
    print("Map section from ChatGPT")
    print(maps_str)
    print("------------END------------")

    c_contents  = cLoaderProg.LOADER_PROG_HEAD + random_str + cLoaderProg.LOADER_PROG_MID_SECTION + maps_str + cLoaderProg.LOADER_PROG_TAIL

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
    mkdir_cmd = "mkdir -p Coverage/" + filename
    mkdir_out = subprocess.run(mkdir_cmd.split(' '))
    # Kcov command
    kcov_cmd = "kcov Coverage/" + filename + "/ ./" + filename + " > /dev/null 2>&1"
    kcov_out = subprocess.run(kcov_cmd, shell=True)
    # Kcov merge
    kcov_merge_cmd = "kcov --merge Coverage/merged_cov/ Coverage/" + filename + "/"
    kcov_merge_out = subprocess.run(kcov_merge_cmd.split(' '))

    found_something = check_for_improvement_in_coverage(filename)
    if found_something:
        ebpf_program = eBPF_program(random_str)
        ebpf_program_deque.append(ebpf_program)
        new_ebpf_map_section = eBPF_map_section(maps_str)
        ebpf_map_section_deque.append(new_ebpf_map_section)

    # Kcov remove
    kcov_remove_cmd = "rm -rf Coverage/" + filename
    kcov_remove_out = subprocess.run(kcov_remove_cmd.split(' '))
    
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

def fuzzer_task(inp):
    global THREAD_PENDULUM

    while STOP_FUZZER !=  True:

        with prof_merge_lock_2:
            pendulum = THREAD_PENDULUM
            THREAD_PENDULUM = not THREAD_PENDULUM

        if pendulum:
            if ebpf_program_deque:
                print("First ebpf_program_deque not empty")
                ebpf_program = ebpf_program_deque.popleft()
                run_heurstic_ebpf_prog(ebpf_program)
            elif ebpf_map_section_deque:
                print("Then ebpf_map_section_deque not empty")
                ebpf_map_section = ebpf_map_section_deque.popleft()
                run_heurstic_ebpf_map_prog(ebpf_map_section)
            else:
                print(pendulum)
                run_single_ebpf_prog()
        else:
            if ebpf_map_section_deque:
                print("First ebpf_map_section_deque not empty")
                ebpf_map_section = ebpf_map_section_deque.popleft()
                run_heurstic_ebpf_map_prog(ebpf_map_section)
            elif ebpf_program_deque:
                print("Then ebpf_program_deque not empty")
                ebpf_program = ebpf_program_deque.popleft()
                run_heurstic_ebpf_prog(ebpf_program)
            else:
                print(pendulum) 
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

if not os.path.exists("Coverage/"):
    os.makedirs("Coverage/")

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
