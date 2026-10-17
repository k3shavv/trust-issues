# Technical Decisions & Evaluation Notes

### 1. What was the most technically challenging part of your implementation, and how did you approach it?
Honestly... getting session states to cleanly reset between pytest runs. The CSRF tokens and cookies kept bleeding into the next test case, which broke things. I had to write explicit teardown fixtures to wipe the session clean after every single run.

### 2. Describe one important design decision you made, and why did you choose that approach over alternatives?
Splitting everything into two separate files (app_vulnerable.py and app_secured.py) on different ports. I thought about using conditional flags in one app... but having two distinct servers made side-by-side testing way cleaner and less confusing.

### 3. What is one limitation or failure case your current implementation does not handle well?
The lockout rate-limiter is just stored in a basic Python dictionary in memory... so if the Flask server restarts, the whole lockout history vanishes. It also won't work across multiple worker processes.

### 4. If you had another week to work on the project, what would you improve first and why?
First thing... swap out that in-memory rate limiter for a proper Redis store so lockouts actually persist. After that, I'd set up database migration scripts and add an audit log for admin actions.