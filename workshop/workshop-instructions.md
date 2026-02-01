# Workshop Instructions

We are going to put our skills to the test to see if you can vibe securely! 

## 1) Get your favorite vibe coding tool set up with a secure system prompt or instruction file
- Write an initial prompt that tells the AI to pay attention to security as it builds, and reference resources like the OWASP Top 10.

## 2) Fork this repo, and check out the demo code in this directory
- Look at the code first yourself, do you see any glaring vulnerabilities? Is there anything you would change on your own?
- If you see anything bad, change it and take notes to share later
- You can run the code with the followning:

``` bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```
Then open a browser and type:

```
http://127.0.0.1:5000
```
And make sure to click the "Initialize demo database" to start the app working. 

## 3) Now run a Semgrep scan on the code
- Run Semgrep to look for any vulnerabilities in the code. Default rule options should be fine
- https://github.com/semgrep/semgrep
- Set up according to your system
- Run a super simple scan like this `semgrep --output=semgrep-report.txt --config auto .`
- After it finishes, look through the output quickly to see what it found
- Then use your AI to help you sort through the results and prioritize what to fix. Focus on critical and high severity issues, and make sure to ask it to consider if something is a false positive.

## 4) Ask the AI to help you fix the vulnerabilities
- Semgrep is only going to find a few issues, others you can see by looking through the code (I left a few comments as hints). Ask the AI to perform a security review on the code and identify any issues it sees.
- Based on anything you found, ask the AI to re-write those sections securely. Always make sure to double check with it that the issue is a true positive, and that the new solution is actually secure and that the code still runs

## 5) Try to vibe a new feature securely!
- Now that you have the hang of it, try to add a new feature to the code. It can be anything, the sillier the better :)
- As you vibe code it, make sure to include instructions for doing so securely and check your work
- Finish out with another Semgrep scan and use the AI to fix anything new you found

## 6) Finally, submit your code to see how secure it is!
- Push your code up to a new repo so it's visible under your own Github.com (ask the AI if you aren't too familiar with how Git works)
- Then, submit the public URL to this form so we can take a look:
- https://app.sli.do/event/qm7gBKF33wmXjEZkf4NAjh
- We will go through it together on the big screen, and you can also try to look at someone else's code to check for vulnerabilities

