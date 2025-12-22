"""
Test program for a 2-bit local branch predictor

Aim the achieve 100% functional coverage
"""

from utils import *
from instruction_annotation_gem5 import *
#from query_receipes import *
import sys

"""
Run a random program
"""
K = 10
module_name = 'bpt_local'
base_path = '/home/mutianzh-debug/experiments/test-program-creation/modules/branch_predictor_local'

if not os.path.exists(base_path):
    print(f"Error: The base path does not exist: {base_path}")
    sys.exit(1) # Exit the script with an error code


"""
Creation of the test program
"""
def generate_test_program_gem5(n_rows):
    code = []

    code.append('        li t0, 5')
    code = add_starters_gem5(code)
    code = exit_program_gem5(code)
    print(f'Length of code is {len(code)}')
    return code


K = 10
run_sim = True

file_name = f'{module_name}_test'
annotation_table_path = f'{base_path}/{file_name}.csv'
trace_path = f'{base_path}/{file_name}.out'

code = generate_test_program_gem5(2**K)
save_code(code, f'{base_path}/{file_name}.S')

if run_sim:
    run_simulation(base_path, file_name)

    annotator = instructionAnnotationGem5(None, annotation_table_path)
    annotator.parse_trace_file(trace_path)
    coverage_measure = annotator.coverage_report(module_name, f'{base_path}/{module_name}_{file_name}_coverage_report.csv')

    print('Coverage measure')
    print(coverage_measure)

    print('Total num of issue')
    print(annotator.modules['issue_queue'].total_issue)

    # module = annotator.modules[module_name]
    # hit_count_table = module.to_frame()
