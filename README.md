# It’s Giving Insecure Vibes: Secure Coding Literacy for Vibe Coders
### Learn how to identify and fix security vulns in vibe coded applications

## Roadmap
1) Intro
2) Exploring vibe coding
3) Common vulns in vibed code
4) Recognizing AI generated code
5) Resolving vulns
6) AI-assisted coding
7) Quiz time!
8) Questions?


## 1) Intro
Betta Lyon Delsordo is a lead application penetration tester at OnDefend, and specializes in code review and AI hacking. She also builds tools to help her pentesting. You can connect with her on LinkedIn: https://www.linkedin.com/in/betta-lyon-delsordo/.

## 2) Exploring vibe coding

- Vibe coding = using AI to write applications with very little edits
- Can be a great time saver: regex!
- But also has many risks, quality issues
- As a team lead on a pod of pentesters (and as a builder of internal software), I see more junior consultants leaning on AI
- We need more awareness of vibed vulnerabilities!


Good vibes:
- Save time writing route code
- Regex (sed/awk syntax)
- Troubleshooting error codes
- Translating from one coding language to another
- Translating comments into different human languages
- Great for prototyping, rapid ideation, internal apps
- Low barrier to entry: juniors and career changers


Bad vibes:
- Less technical users mean less understanding of code
- Very bad for scaling, troubleshooting, maintaining 
- Can prevent learning and growth
- General lack of security awareness
- Very common to lack authorization and sanitization
- Public facing apps draw hacker attention -> easy breach



## 3) Common vulns in vibed code
- Exposing sensitive information - hard coded API keys and creds
- Insecure default passwords, unencrypted traffic, no auth checks
- Detailed comments about exactly how to log in and exploit it
- Displaying way too much information to public users
- Very noisy exploits (if trying to evade detection)
- No user input sanitization
- Pulling in malicious libraries masquerading as open source projects
- Pasting proprietary code into public/online LLMs that train on it
- Downloading malicious coding tools that claim to do ‘magic’ 

## 4) Recognizing AI generated code
- Emoji comments!
- Perfect formatting, especially for large tables or JSON that would be difficult for a human to type
- Very perfect print statements with verbose language
- Redundant or unnecessary functions
- Lack of user comprehension about what the code does
- Crashes or fails without meaningful errors, no evidence of incremental development or debugging or unit tests
- Nonsensical imports
- Function stubs that don’t do anything
- No attempt to integrate with existing environment



## 5) Resolving vulns
- Learn some basic application security: OWASP Top 10 is a great place to start
- Prompt with emphasis on secure coding
- Ask the AI to review its own code for security
- Adversarial AI: ask another AI to find the vulnerabilities
- Always ask for secure defaults, no hard coding creds, do user input sanitization, authorization checks
- Do a thorough review of the code, spend more time reviewing than you did coding!
- Get help from someone who knows, and keep learning how to actually code
- Don’t put things into production or accept sensitive data if you don’t know what you’re doing
- Train junior members on the risks of AI coding and keep training them on real, manual coding
- Make sure your team understands the risks of sharing code with public/online LLMs and train them to use private/local alternatives


Offline AI:
- Encourage team members to use offline or private AI solutions
- Especially important with pentesting, national security, proprietary code, sensitive datasets
- GPT4All is a great option: https://www.nomic.ai/gpt4all
- Use with a model like Llama3, and turn off analytics and data lake on startup -> then fully private



## 6) AI-assisted coding
- Instead of having the AI write everything, use it as a companion to help you troubleshoot tough errors
- Try to code out the entire application as you normally would manually, but then ask for help when you get tough errors or are exploring new tech stacks
- Get help with troubleshooting and ask for secure architecture advice
- Ask an AI to review your code for vulnerabilities
- Ask for tutoring and quiz sessions to help you learn more kinds of vulnerabilities
- Use vibe coding for quick, internal scripts (like regex or awk/sed) and know when go manual for bigger projects


## 7) Quiz time!
See slides for the snippets... 

## 8) Questions?
Feel free to follow up with the speaker on LinkedIn with any questions you have: https://www.linkedin.com/in/betta-lyon-delsordo/.
