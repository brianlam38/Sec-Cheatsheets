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
* Have a set of security goals, coming from an assessment of the software risks that you face.
* Use these goals to prioritise code that should be reviewed and the criteria used to review it.
* Set review priorities down to the granularity of individual programs. Don't further subdivide the code.
* For inspiration, look at results of previous code reviews for the same program / similar programs. Previously discovered errors often slip back in.

2. Run Tools
* Get the code into a compilable state before you begin analysing it.
* Add custom rules to detect errors specific to your program.
* Establish / refer to your organisation's set of secure coding guidelines.
* Refer to previously identified errors and write a rule to detect similar situations.

3. Review Code
* *Neighbourhood Effect*: find more problems next to the tool-reported issue.
* Reviewing an issue = verifying the assumptions that the tool made when it reported the issue.
* If you discover an issue during code review, which the tool has missed, then write custom rules to detect instances of the same problem and re-run the tool.
* Make sure to store the results of the code review properly so that they will be useful for future code reviews.
* Also use the results for *Security Training*, focusing on real problems that are relevant to your company.

4. Make Fixes
* Results from a code review need a good explanation of the risk involved.
* Is there enough time to make a fix?
* Is there a large clump of issues around a particular module/feature? => Maybe step back and look for a design-related fix.
* The most long-term approach to fix issues is improve security training.
* All fixes must be verified.

**Steer clear of the Exploitability Trap**

Review teams are often pulled down into exploit development. When a programmer says *"I won't fix that unless you can prove it's exploitable"*, that is an **Exploitability Trap**. This is bad because:
* Developing exploits is time-consuming. This time is better spent looking for more problems.
* Developing exploits is a whole other skill itself. Can't develop an exploit != Defect is not exploitable.

Reasons to not get stuck in the Exploitability Trap:
* Risk from shipping vulnerabilities > Risk from introducing new bugs from the bug fix.
* Ignored vulnerabilities may lead to further vulnerabilities (chained) which could become more serious.
* Vulnerabilities don't need to be exploitable to damage a company e.g. reputation damage from reporting the vuln.

**Adding security review to an existing development process**





## PART 2: Pervasive Problems
*Pervasive security problems that impact software, regardless of functionality*





## PART 3: Features and Flavours
*Security problems with that affect common types of programs and specific software features*





## PART 4: Static Analysis in Practice
*Practical exercises on Static Analysis*









