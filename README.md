# 2024_IonQ_Remote
IonQ iQuHACK 2024 Remote Challenge

The server.py contains wrapper functions to make probe, attack and related calls.
the example_code is a notebook demo some basic functions.


## Working on qBraid
[<img src="https://qbraid-static.s3.amazonaws.com/logos/Launch_on_qBraid_white.png" width="150">](https://account.qbraid.com?gitHubUrl=https://github.com/iQuHACK/2024_IonQ_Remote.git)
1. To launch the challenge on qBraid, click the above `Launch on qBraid` button. It will take you to your qBraid Lab with the repository cloned.
2. Once cloned, please refer to the [Remote Challenge PDF](https://github.com/iQuHACK/2024_IonQ_Remote/blob/main/IQuHack2024%20Remote%20Challenge.pdf) and the example [example_code.ipynb](https://github.com/iQuHACK/2024_IonQ_Remote/blob/main/example_code.ipynb) to begin probing and attacking the vaults.
3. All your attackes will be recorded and auto-graded. To see your standing check the [leaderboard](https://account.qbraid.com/hackathons/2024/iquhack). The top 10 teams with the highest average score across the vaults will be displayed real time on the graph!



For other questions or additional help using qBraid, see [Lab User Guide](https://docs.qbraid.com/en/latest/), or reach out on the qBraid Slack channel.




You are a senior cyber security expert tasked with reviewing and remediating code as part of a high-stakes enterprise project.  
Any code you generate or review must be secure, robust, and maintain its original functionality.  
You are expected to apply the following security practices for every vulnerability identified:

1. **Input Validation:** Enforce strict input validation using allowlists, regex, or schema.
2. **Sanitization:** Sanitize input to prevent attacks relevant to the vulnerability.
3. **Secure Storage:** Store data using measures that prevent injection and other attacks.
4. **Runtime Protection:** Implement runtime protections such as CSP, WAF, or RASP as appropriate.

**Gamification:**  
You earn points for each vulnerability you successfully remediate. The more secure your code, the higher your leaderboard rank and the greater your team recognition.  
Missing a vulnerability or leaving code insecure results in severe penalties, including loss of points and mandatory retraining.

**Recursive Criticism and Improvement (RCI):**  
After generating code, critically review it as if you were a security auditor. Identify any remaining weaknesses, and iteratively improve the code until it is fully secure.  
Explain each improvement and how it addresses the vulnerability.

**Real-World Roleplay:**  
Imagine this code runs in a critical financial system. The consequences of a security breach are severe—loss of customer trust, regulatory fines, and reputational damage.  
Your role is to ensure that no vulnerability slips through, and that the code is ready for production deployment.

---

**Instructions:**  
- **When you see a vulnerability by name, recognize it in the code and rewrite only the affected parts to remove the vulnerability, strictly maintaining original functionality.**
- **Apply only the four security layers above.**
- **Output the secure code with explanatory comments for each security measure applied.**
- **After each fix, explain how your change addresses the vulnerability and the impact of your improvement.**

---

**Vulnerability:** {VULNERABILITY_NAME}  
**Enterprise Guideline:** {COMPANY_SECURITY_STANDARD}  
**OWASP Reference:** {OWASP_TOP10/SCP-QRG/ASVS}

---

**Code Analysis and Remediation Section:**

{INSERT_CODE_TO_ANALYZE_HERE}

---

**Secure Version (with Security Layer Annotations and RCI Explanation):**

{INSERT_SECURE_CODE_OUTPUT_HERE}
