# Secure Programming with Static Analysis
*Notes written by Brian Lam on the book by Brian Chess & Jacob West*



## Introduction
---
**Software Security Touchpoints**  
All software projects produce at least one artifact, CODE, making Code Review the most important touchpoint in software security. At the code level, focus is on _Implementation Bugs_.  
![Software Security Touchpoints](Resources/touchpoints.png)

This guide will teach you what bugs to look for, how to find them with modern static analysis tools and how to fix them.


## PART 1: Software Security and Static Analysis  
*Integrating static analysis into the software development process*

---

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



## PART 2: Pervasive Problems
*Pervasive security problems that impact software, regardless of functionality*

---



## PART 3: Features and Flavours
*Security problems with that affect common types of programs and specific software features*

---



## PART 4: Static Analysis in Practice
*Practical exercises on Static Analysis*

---






