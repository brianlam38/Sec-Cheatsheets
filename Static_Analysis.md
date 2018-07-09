# Secure Programming with Static Analysis
*Notes written by Brian Lam on the book by Brian Chess & Jacob West*



## Introduction

**Software Security Touchpoints**  
All software projects produce at least one artifact, CODE, making Code Review the most important touchpoint in software security. At the code level, focus is on _Implementation Bugs_.  
![Software Security Touchpoints](Resources/touchpoints.png)

This guide will teach you what bugs to look for, how to find them with modern static analysis tools and how to fix them.


## PART 1: Software Security and Static Analysis  
*Integrating static analysis into the software development process*



**Defensive programming is not enough**  
``` C
// BAD (no defence)
void printMsg(FILE* file, char* msg) {
  fprintf(file, msg);
}

// SLIGHTLY BETTER (defensive programming with basic error handling)
// Still exploitable i.e. Format String Attack: AAA1_%08x.%08x.%08x.%08x.%08x.%n
void printMsg(FILE* file, char* msg) {
  if (file == NULL) {
    logError("attempt to print message to null file");
  } else if (msg == NULL) {
    logError("attempt to print null message");
  } else {
    fprintf(file, msg);
  }
}

// BETTER (more secure by enforcing a fixed format string)
// "%.128s" = string of max len 128
void printMsg(FILE* file, char* msg) {
  if (file == NULL) {
    logError("attempt to print message to null file");
  } else if (msg == NULL) {
    logError("attempt to print null message");
  } else {
  }
    fprintf(file, "%.128s", msg);
}
```

**Static Analysis in the bigger picture**  

Most software development methods can be outlined in the same four steps:
1. *Plan*: gather requirements, create a design and plan testing.
2. *Build*: write the code and the tests.
3. *Test*: run tests, record results and determine the quality of code.
4. *Field*: deploy the software, monitor its performance and maintain it.

Focus should be put on addressing the ROOT CAUSE of security problems, done during the *Plan* and *Build* stages and solved by performing Static Analysis, Architectural Risk Assessments and writing Security Requirements.

**Solving Problems with Static Analysis**  

*Type Checking*  
* Type checking is typically not given much thought because types are usually defined by programming languages and enforced by the compiler (except for dynamically typed languages such as Python and Shell as opposed to statically typed such as C).

*Style Checking*
* Style checking on an existing large codebase provides marginal benefit and the cost of great inconvenience.
* Use a *Linter* e.g. ES-Lint for Javascript for performing style checks on large sets of code.

*Program Understanding*  
* Best to use the original design to understand a program e.g. UML diagram rather than reverse engineering the design based on implementation.

*Program Verification and Property Checking*  
* A program verification tool accepts a specification and a body of code then attempts to prove that code adheres to the specification.
* Example of program that will cause errors in a Program Verification tool:
```C
// Specification: Allocated memory should always be free'd

// Code: allocate memory for an input/output buffer
inBuf = (char *) malloc(bufSz);
if (inBuf = NULL)
  return -1;
outBuf = (char *) malloc(bufSz);
if (outBuf == NULL)
  return -1;
```





## PART 2: Pervasive Problems
*Pervasive security problems that impact software, regardless of functionality*





## PART 3: Features and Flavours
*Security problems with that affect common types of programs and specific software features*





## PART 4: Static Analysis in Practice
*Practical exercises on Static Analysis*









