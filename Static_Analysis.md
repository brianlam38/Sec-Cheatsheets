# Secure Programming with Static Analysis
*Notes written by Brian Lam on the book by Brian Chess & Jacob West*



## Introduction

**Software Security Touchpoints**  
All software projects produce at least one artifact, CODE, making Code Review the most important touchpoint in software security. At the code level, focus is on _Implementation Bugs_.  
![Software Security Touchpoints](Resources/touchpoints.png)

This guide will teach you what bugs to look for, how to find them with modern static analysis tools and how to fix them.


## PART 1: Software Security and Static Analysis  
*Integrating static analysis into the software development process*

**Static Analysis in the bigger picture**  

Most software development methods can be outlined in the same four steps:
1. *Plan*: gather requirements, create a design and plan testing.
2. *Build*: write the code and the tests.
3. *Test*: run tests, record results and determine the quality of code.
4. *Field*: deploy the software, monitor its performance and maintain it.

Focus should be put on addressing the ROOT CAUSE of security problems, done during the *Plan* and *Build* stages and solved by performing Static Analysis, Architectural Risk Assessments and writing Security Requirements.

**Static Analysis in practice**  

Using static analysis tools involve a trade-off between *Time/Memory Resources* vs. *Analysis Scope*.
* Larger scope (i.e. code base of a program) means more time and memory to perform the analysis.
* Smaller scope (i.e. code in a single function) means less time and memory to perform the analysis.

Benchmark different static analysis tools against the same codebase to test their effectiveness.
* Look for open-source, static analysis benchmarking tools and test it against known, vulnerable programs (i.e. hackerzon)

Challenges of Static Analysis:
* Making sense of the program (building an accurate program model / design)
* Making good trade-offs between precision, depth and scalability.
* Looking for the right set of defects.
* Presenting easy-to-understand results and errors.
* Integrating easily with the build system and integrated development environments.

**Performing a Code Review**

The Code Review Cycle:
[ INSERT IMAGE HERE ]

1. Establish Goals


2. Run Tools

3. Review Code

4. Make Fixes

## PART 2: Pervasive Problems
*Pervasive security problems that impact software, regardless of functionality*





## PART 3: Features and Flavours
*Security problems with that affect common types of programs and specific software features*





## PART 4: Static Analysis in Practice
*Practical exercises on Static Analysis*









