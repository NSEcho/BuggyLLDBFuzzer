# In the case of NSString * aa = [NSString stringWithFormat:@"%@ => %@", @"something", @"else"];
# NSString - $rdi
# stringWithFormat: - $rsi
# @"%@ => %@" - $rdx
# @"something" - $rcx
# @"else" - $r8
# So, in order to overwrite/fuzz the "else", we need to call
# fuzz stringWithFormat newValue 5
# (lldb) fuzz stringWithFormat newValue 5
# (lldb) c
# Process 84888 resuming
# 2021-10-21 22:37:08.679380+0200 testing[84888:2877517] String is something => else
# 2021-10-21 22:37:11.916889+0200 testing[84888:2877517] String is something => newValue22:37:11

import lldb
import shlex
from datetime import datetime

input = None
addr = None
arg_num = None

reg_name = {
    '1': 'rdi',
    '2': 'rsi',
    '3': 'rdx',
    '4': 'rcx',
    '5': 'r8',
    '6': 'r9'
}

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f BuggyLLDBFuzzer.fuzz fuzz')

def fuzz(debugger, command, result, internal_dict):
    global input
    global addr
    global arg_num
    args = shlex.split(command)

    func = args[0]
    input = args[1]
    arg_num = args[2]

    # create the NSMutableString holding our initial input that will get mutated
    command = r'''
        @import Foundation;
        NSMutableString *fuzzd = (NSMutableString*)[[NSMutableString alloc] init];
        [fuzzd setString:@"{}"];

        fuzzd;
    '''.format(input)
    expr = "expression -lobjc -O -- " + command

    res = executeCommand(command)
    addr = res.GetAddress()

    target = debugger.GetSelectedTarget()
    breakpoint = target.BreakpointCreateByRegex(func)
    breakpoint.SetScriptCallbackFunction("BuggyLLDBFuzzer.handle")



def handle(frame, bp_loc, dict):
    thread = frame.GetThread()
    process = thread.GetProcess()
    debugger = process.GetTarget().GetDebugger()
    interpreter = debugger.GetCommandInterpreter()

    debugger.SetAsync(False)

    fuzzd = algo()

    # Write new value inside our NSMutableString
    ret = lldb.SBCommandReturnObject()
    expr = 'expression -lobjc -- (NSMutableString*)[' + str(addr) + ' setString:@"' + fuzzd + '"]'
    interpreter.HandleCommand(expr, ret)

    reg = reg_name[arg_num] 

    # Fill the argument accordingly
    ret_value = lldb.SBCommandReturnObject()
    expression = 'register write ' + reg + ' ' + str(addr)
    interpreter.HandleCommand(expression, ret_value)

    return False

def algo():
    now = datetime.now()
    return input + now.strftime("%H:%M:%S")


def executeCommand(command):
    debugger = lldb.debugger
    process = debugger.GetSelectedTarget().GetProcess()
    frame = process.GetSelectedThread().GetSelectedFrame()
    
    expr_options = lldb.SBExpressionOptions()
    expr_options.SetIgnoreBreakpoints(False);
    expr_options.SetFetchDynamicValue(lldb.eDynamicCanRunTarget);
    expr_options.SetTimeoutInMicroSeconds (30*1000*1000) # 30 second timeout
    expr_options.SetTryAllThreads (True)
    expr_options.SetUnwindOnError(False)
    expr_options.SetGenerateDebugInfo(True)
    expr_options.SetLanguage (lldb.eLanguageTypeObjC)
    expr_options.SetCoerceResultToId(True)
    return frame.EvaluateExpression(command, expr_options)
