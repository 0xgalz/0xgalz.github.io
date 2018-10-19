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

<picture>
<picture>

## Finding the Log Function Names
Since this code had way too many debug prints I decided to write something to deal with them.
There are a few ways to figure out what functions deal with debug prints.
One way is to find those functions based on libc function calls inside them or by their behavior, this is a more complex and time-consuming way but it’s the more elegant one.
The second way is quick and dirty, it’s recommended especially when you don’t have a lot of time and need to have quick wins. In this case, just look at the strings in the executable and  find suspicious debug prints, after you found them look if some functions received them as arguments. If a function repeatedly gets called with debug prints as arguments you can use it in the script. 
Before creating the script I figured out that approximately 10 different functions are dealing with debug prints, and I also saw the registers where the string argument with the DbgPrint was stored in. 

# My Solution
My goal was to change IDA’s default function names to be more indicative based on their debug prints.

*For example:*
<picture>

The next parts will shed some light on the different parts of the script.

## Putin it all together
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







## Welcome to GitHub Pages

You can use the [editor on GitHub](https://github.com/0xgalz/0xgalz.github.io/edit/master/index.md) to maintain and preview the content for your website in Markdown files.

Whenever you commit to this repository, GitHub Pages will run [Jekyll](https://jekyllrb.com/) to rebuild the pages in your site, from the content in your Markdown files.

### Markdown

Markdown is a lightweight and easy-to-use syntax for styling your writing. It includes conventions for

```markdown
Syntax highlighted code block

# Header 1
## Header 2
### Header 3

- Bulleted
- List

1. Numbered
2. List

**Bold** and _Italic_ and `Code` text

[Link](url) and ![Image](src)
```

For more details see [GitHub Flavored Markdown](https://guides.github.com/features/mastering-markdown/).

### Jekyll Themes

Your Pages site will use the layout and styles from the Jekyll theme you have selected in your [repository settings](https://github.com/0xgalz/0xgalz.github.io/settings). The name of this theme is saved in the Jekyll `_config.yml` configuration file.

### Support or Contact

Having trouble with Pages? Check out our [documentation](https://help.github.com/categories/github-pages-basics/) or [contact support](https://github.com/contact) and we’ll help you sort it out.
