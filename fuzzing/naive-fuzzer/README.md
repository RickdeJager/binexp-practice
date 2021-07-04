# Naive Exec Fuzzer

This fuzzer is a near copy of the simple fuzzer Gamozo creates on day 2 of fuzz week.   
You can find the recording here: https://www.youtube.com/watch?v=iM3s8-umRO0  
  
I'm testing it on [a vulnerable test program](../../vulnerable_programs/text_file_parser/), which has a pretty glaring stack overflow.


### Directory setup
```
tree -L 1
.
├── Cargo.lock
├── Cargo.toml
├── corpus
├── crashes
├── README.md
├── src
├── target
└── tempinputs
```
