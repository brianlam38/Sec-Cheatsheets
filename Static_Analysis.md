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
    fprintf(file, "%.128s", msg);
  }
}
```

**Static Analysis in the bigger picture**  

Most software development methods can be outlined in the same four steps:
1. *Plan*: gather requirements, create a design and plan testing.
2. *Build*: write the code and the tests.
3. *Test*: run tests, record results and determine the quality of code.
4. *Field*: deploy the software, monitor its performance and maintain it.

Focus should be put on addressing the ROOT CAUSE of security problems, done during the *Plan* and *Build* stages and solved by performing Static Analysis, Architectural Risk Assessments and writing Security Requirements.

**Classifying Vulnerabilities**  
*Common Weakness Enumeration (CWE)* focuses on a vulnerability, not an instance of a vulnerability within a product/system.  
*Common Vulnerability Enumeration (CVE)* focuses on a specific instance of a vuln within a product/system, not the underlying flaw.

"The Seven Pernicious Kingdoms" (as opposed to OWASP Top 10)

1. Input Validation and Representation: Handling of input.

2. API Abuse: Contract between API caller / API callee being broken by either side. E.g. `java.util.Random` returning non-random values.

3. Security Features: Authentication, access control, confidentiality, cryptography, privilege management. E.g. hard-coding passwords, leaking confidential data between users or writing to privileged programs etc.

4. Time and State: Vulnerabilities related to shared-state among distributed systems. E.g. online multiplayer games and duplicating money to provide an unfair advantage. (**Race Conditions**)

5. Error Handling: Producing errors that reveal too much info, or not enough at all.

6. Code Quality: De-referencing NULL pointers, entering into infinite-loops could lead to a Denial-of-Service.

7. Encapsulation: Drawing strong boundaries. E.g. between validated vs. un-validated data, between one user's data vs. another's, between data that users are allowed to see vs. data they are not allowed to.

8. Environment: Environment (outside) related vulnerabilities. E.g. configuration files.








## PART 2: Pervasive Problems
*Pervasive security problems that impact software, regardless of functionality*





## PART 3: Features and Flavours
*Security problems with that affect common types of programs and specific software features*





## PART 4: Static Analysis in Practice
*Practical exercises on Static Analysis*









