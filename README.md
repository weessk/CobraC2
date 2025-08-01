# 🐍 CobraC2 🐍
### *Post-Exploitation Tool*

![GitHub stars](https://img.shields.io/github/stars/weessk/CobraC2?style=social)
![Forks](https://img.shields.io/github/forks/weessk/CobraC2?style=social)

```
   ______      __               _____ __         ____
  / ____/___  / /_  _________ _/ ___// /_  ___  / / /
 / /   / __ \/ __ \/ ___/ __ `/\__ \/ __ \/ _ \/ / /
/ /___/ /_/ / /_/ / /  / /_/ /___/ / / / /  __/ / /
\____/\____/_.___/_/   \__,_//____/_/ /_/\___/_/_/
```

## What the fuck is this?

CobraC2 is a simple but powerful Command and Control server. You run it, you generate a PowerShell payload, the target runs it, and *BAM*... you get a fucking shell. Encrypted, stable, and easy as hell to use.

## The Good Shit (Features)

- **Fucking Encrypted Comms:** Uses AES so no one can snoop on your shit.
- **PowerShell Venom:** Generates a one-liner payload to get things going.
- **Army of Snakes:** Handles multiple targets at once. List 'em, interact with 'em.
- **File Pushing & Pulling:** `upload` your tools, `download` their sweet, sweet loot.

## How to Pwn (Usage)

1.  **Clone this shit:**
    `git clone https://github.com/weessk/CobraC2.git && cd CobraC2`

2.  **Install the boring stuff:**
    `pip install -r requirements.txt`

3.  **Fire up the server:**
    `python CobraC2.py`

4.  **Craft your venom (`generate`):**
    - The server will ask for your IP. Give it to him.
    - It'll spit out a long `powershell -e ...` command. Copy that.

5.  **Unleash the snake:**
    - Get your target to run that command. Be creative. Phishing, bad USB, you know the drill.

6.  **Command your army:**
    - `list` to see your beautiful new bots.
    - `interact <id>` to jump into a shell and start breaking things.

## A "Disclaimer"
I'm not your dad. If you use this to do illegal shit and get caught, that's on you. Use it for "education" or whatever you need to tell yourself to sleep at night. Don't be a dick... unless you're good at it.
