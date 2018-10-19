# Automaticly Mapping Binaries With Debug Print Using IDAPython

This blog gives a short overview on a script I wrote that replaces the default function names in IDA with names constructed from debug prints, hopefully it will also provide the basic knowledge for you to create one of your own.

# Disclaimer
>This is an explanation about a small script I wrote which helped me map large binaries in seconds rather than weeks.
I encourage anyone to modify the script to their own use.
I used this code for my own private research - buy me a beer if you find it helpful or fix a bug. 

# The Problem
The main problem I had, was that I needed to map a large binary without any symbols. I had a limited time frame for the binary’s first mapping, so I had to find a more effective way to do that. I’m a big fan of writing scripts for IDA, especially for the mapping part, and this is also what I did in this case. So in order to automate the mapping process I used the naive way: I looked if there were any debug prints. Fortunately, the binary had a lot of them.

# Practical Examples
From the assembly side the debug prints are gold mines. They can show the purpose of the function and also can show the real filenames which help understanding what module this function is part of.
It’s important to note that the code I originally researched was 8086 assembly running on a x64 OS, while most of the functions are using *fastcall* calling convention. Thus I'm using fastcall as an example in my blog.

![alt text](https://github.com/0xgalz/0xgalz.github.io/blob/master/DbgPrintExample_Error.JPG?raw=true "debug print example- error")
Fig.1- Debug print with indicative error string

![alt text](https://github.com/0xgalz/0xgalz.github.io/blob/master/DbgPrintExample_Path.JPG?raw=true "debug print example- filename")
Fig.2- Debug print with with the source filename 

### Finding the Log Function Names
Since this code had way too many debug prints I decided to write something to deal with them.
There are a few ways to figure out what functions deal with debug prints.
One way is to find those functions based on libc function calls inside them or by their behavior, this is a more complex and time-consuming way but it’s the more elegant one.
The second way is quick and dirty, it’s recommended especially when you don’t have a lot of time and need to have quick wins. In this case, just look at the strings in the executable and  find suspicious debug prints, after you found them look if some functions received them as arguments. If a function repeatedly gets called with debug prints as arguments you can use it in the script. 
Before creating the script I figured out that approximately 10 different functions are dealing with debug prints, and I also saw the registers where the string argument with the DbgPrint was stored in. 

# My Solution
My goal was to change IDA’s default function names to be more indicative based on their debug prints.

*For example:*
![alt text](https://github.com/0xgalz/0xgalz.github.io/blob/master/AutoFuncCapture_BeforeAfter.jpg?raw=true "debug print example- error")
Fig.3- Before and after changing the function name with the script 
The next parts will shed some light on the different parts of the script.

### Putin it all together
As I see it, there are at least 2 ways to find the places log functions were called from, the lazy way and the less lazy way.
### The lazy way 
Go over all the assembly and look for a “call” instruction, followed by an argument with the log functions name.
I decided to organize the function names as part of a global dictionary:
```python
FUNCTIONS_REGISTERS = {Function_Name:Register, Function_Name_1, Register_1... }
```
Function names as the keys, and their values are the relevant register with the debug print.
For example if the code has both the functions in Fig.3 and Fig.4, it would look like: 

```python
FUNCTIONS_REGISTERS = {“gz_WriteLogFile”: “rdx”, “g_LogError”: “rdx”}
```
The script I wrote for that part is as follows
```python
curr_addr = MinEA()
end = MaxEA()
while curr_addr < end:
   if curr_addr == idc.BADADDR:
       break
   elif idc.GetMnem(curr_addr) == 'call':
       if idc.GetOpnd(curr_addr, 0) in FUNCTIONS_REGISTERS.keys():
		pass
```
### The less lazy way 
The less lazy way I thought about was to use xref to the relevant functions found. In this way I used the same dictionary of function names.
Here, what I did was to find the xref addresses to each function, namely, the addresses of the function calls.
```python
for function_name in FUNCTIONS_REGISTERS.keys():
  func_addr = idc.LocByName(function_name)
    a = idautils.XrefsTo(func_addr, 1)
    addr = {}
    for xref in a:
        curr_addr = xref.frm  # ea in func
        if curr_addr == idc.BADADDR:
            pass
```

## Get Functions Arguments
The functions have the debug prints stored in registers that were assigned prior to the call instruction. Because I have the address of the call instruction itself (from the previous step) I needed to taint backwards and find the relevant register value, starting from the call instruction address.
 picture>
The code that gets the address name of the register assignment is as follows
```python
def get_string_for_function(call_func_addr, register):
   """
   :param start_addr: The function call address
   :return: the string offset name from the relevant register
   """
   cur_addr = call_func_addr
   start_addr = idc.GetFunctionAttr(cur_addr, idc.FUNCATTR_START)
   cur_addr = idc.PrevHead(cur_addr)
   # go through previous opcodes looking for assignment to the register
   while cur_addr >= start_addr:
       if idc.GetMnem(cur_addr)[:3] == "lea" and idc.GetOpnd(cur_addr, 0) == register:
           str_func = idc.GetOpnd(cur_addr, 1)
           return str_func
       cur_addr = idc.PrevHead(cur_addr)
   return str_func
```
Once we have the debug print address, we want to get the actual string it references .
The following code shows how it can be done (For example: changing: “aErrorSavingFil” -> “Error saving file %1”.
We can do that by simply extract the address from its name and then get the string stored inside.
```python
 func_name = idc.GetString(idc.LocByName(addr))
```
## From Debug Prints to Function Name
Before changing the function name we should fix the debug prints format a little, since the final function name that will be presented should be clean and readable, so I created a function in the script that does that. 

Disclaimer: The function I present here is not the whole function I used, it only has general changes in the DbgPrints, if you would like to create script like this for your own, you should write a function that changes the relevant parts in your debug print formats.

In this function there is also the extraction of the DbgPrint string from the address name.
```python
 def get_fixed_source_filename(addr):
   """
   :param addr: The address of the source filename string
   :return: The fixed source filename's string
   """
   func_name = idc.GetString(idc.LocByName(addr)).replace("/", "_").replace(" ", "_")
   func_name = "AutoFunc_" + func_name
   # if the debug print is a path, delete the extension
   if func_name[-2:] == ".c" or func_name[-2:] == ".h":
       func_name = func_name[:-2]
   # you can add whatever you want here in order to have your preferred function name
   return func_name
```
It is also important to note that one of the functions in the code checks whether the function was auto-generated by IDA or by the script and the script only change those functions.
If you reversed the code and changed a function name without the prefix of “AutoFunc” the code will not change the function name. 
```python
def is_function_name(cur_func_name):
   """
   :param cur_func_name: the current function name
   :return: True/ False - depends if the name is the default name or auto-generated one,
            Names that were chosen by the user will stay the same
   """
   if cur_func_name[:9] == "AutoFunc_":
       return True
   elif cur_func_name[:4] == "sub_":
       return True
   else:
       return False
```
## Change Function Name
This is the last part of the script, which is changing the function name. It can easily be done by running the following command:
```python
idaapi.set_name(function_start, new_filename, idaapi.SN_FORCE)
```
It is important to note that the idaapi.SN_FORCE flag can only be used in IDA 7 version and above. 

## Handling Errors
Since I had a large binary some of the debug functions I found once in a while acted a little different, although 99.9% of the time no error occured, I couldn’t ignore these cases.
Even if some error occurs the script will continue running on all the other functions, but I wanted to track the error and change the failed functions names.  
When those errors happen, messages appear in the output window:

![alt text](https://github.com/0xgalz/0xgalz.github.io/blob/master/Errors.png?raw=true "Error Handling- Example")
Fig.4- IDA Output Window, on error

Error messages have the address of the failure, the log function name and the current name of the function.

# The End
Basically, it’s not rocket science and this is in general all the code parts in my script. Hopefully it will help people in their path to increase code coverage or just open them to the magical world of IDAPython.  I hope you enjoyed reading, any feedback is welcome :) You can find to full code in [here](https://gist.github.com/0xgalz/cce0bfead8458226faddad6dd7f88350).
