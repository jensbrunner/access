\# Access Policy Engine



A small Java practice project implementing a simple access-control policy engine.



The project models users, resources and access requests, then evaluates whether a request should be allowed based on configurable resource policies.



\## Features



\* Role-based access checks

\* Optional MFA requirement

\* Business-hours restrictions

\* IP-prefix allow lists

\* Multiple policies per resource

\* Explicit denial reasons

\* Input validation for invalid requests

\* Unit tests with JUnit 5



\## Example rules



A resource policy can require that a user:



\* has at least one required role

\* has completed MFA

\* accesses the resource during business hours

\* connects from an allowed IP prefix



If multiple policies exist for the same resource, access is granted as soon as one policy matches. If none match, the engine returns the denial reasons.



\## Tech stack



\* Java

\* Maven

\* JUnit 5



\## Project structure



```text

src/

&#x20; main/java/ch/jens/access/

&#x20;   AccessPolicyEngine.java

&#x20;   AccessDecision.java

&#x20;   AccessRequest.java

&#x20;   ResourcePolicy.java

&#x20;   User.java



&#x20; test/java/ch/jens/access/

&#x20;   AccessPolicyEngineTest.java

```



\## Running the tests



From the project root:



```bash

mvn test

```



On Windows CMD:



```cmd

mvn test

```



\## What this project demonstrates



This project was built as Java practice around:



\* clean domain modelling with records

\* simple authorization logic

\* defensive input validation

\* deterministic time-dependent tests using `Clock`

\* test-driven coverage of access-control edge cases



