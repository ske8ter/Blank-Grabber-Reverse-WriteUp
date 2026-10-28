> ⚠️ WARNING — If you want to repeat the actions from this write-up, use a virtual machine with no real data and Defender/AV disabled, NOT your own host machine. Thanks for protecting yourself! Also, AI was used to check and correct grammar mistakes.

## Decompiling and unpacking the actual Python file

For this example the binary was taken from <https://app.any.run/tasks/93e36359-8de0-4389-a308-f389ac993a7d/>, since I couldn't find the original builder to generate a fresh copy for educational purposes.

After downloading the sample, we can unzip it using the default password for ANY.RUN sample files — `infected`.

Next we want to check its metadata to confirm it's a Python-packed file, and to be 100% sure it's actually Blank Grabber. I prefer VirusTotal for this step.

![VirusTotal metadata / detections](images/Pasted%20image%2020261028165116.png)

As we can see in the report (<https://www.virustotal.com/gui/file/eaff5998ce9359030f5c063b013487a056b5356a07465e6124ff8ee37bbd4006/detection>), a lot of security vendors flag it as a Python executable (referred to as **PE** from here on). If that's not enough to be sure it's a PE, we can just use **pyinstxtractor**: <https://github.com/extremecoders-re/pyinstxtractor>

After unpacking the PE we only care about the `.pyc` files (for this sample, and most of the time). As we can see, we have several of them.

![Extracted .pyc files](images/Pasted%20image%2020261028165551.png)

Now we look for custom names like `main.pyc` / `app.pyc` / `test.pyc`. For our sample we got `d67618d5-891f-4b47-b8db-be0adebb384a.pyc`.

After locating the file we have two options:

1. Use a local decompiler like `decompyle3` or similar.
2. Use an online tool like <https://pylingual.io> — which I prefer, mostly because of my PC's performance.

As decompiled source we get the result at <https://pylingual.io/view_chimera?identifier=70f090e2265070da46df7c0f494e57a0a005d09dc0d267f39f7f1b1f84dfcfd6> (may not work in the future). Since there are no errors or conflicts, we can use the **Python code** tab.

![pylingual decompiled source](images/Pasted%20image%2020261028170100.png)

Here we can see the logic that unpacks the binary of the actual virus. Since we have the source, we can modify it so it **unpacks and decrypts the file without executing it** — that's what we'll do next.

But first, look at **line 10** in the screenshot: it uses `pyaes` for `AESModeOfOperationGCM`, which recent versions of `pyaes` don't really support — so we'll use **pycryptodome** instead.

Here's the patch code we'll use:

![First patch — decrypt without executing](images/Pasted%20image%2020261028171202.png)

After running the patch (it has to be in the same folder as the `blank.aes` file) there's no output, but checking the folder shows a new archive called `blank_aes.zip` created by our patch. Now we can move on to the next layer of obfuscation. Inside the archive we only have one file.

![blank_aes.zip — one file inside](images/Pasted%20image%2020261028171631.png)

## Deobfuscation after unpacking

As in the previous section, I'll use pylingual to get through the `.pyc` file. After a while we can see (<https://pylingual.io/view_chimera?identifier=43789401e658059df5f258b17726459169618d86f007b6b17b3fb538e4cc350c>, may not work in the future) that the generated Python code can't be used as 100% accurate code — it fails with a `Compilation Error`. So we're forced to go through the **original bytecode** to validate that it works as generated. Thanks to pylingual, the bytecode is already included in the result, so we don't need other tools. After going through the bytecode we can create our second patch, which will be safe to launch.

![Second patch](images/Pasted%20image%2020261028173806.png)

Replace the `"...."` with the payload from line 12 (shown below), then run the code. Again there's no output, but a file named `source.py` is created with the next layer of obfuscation.

![Payload from line 12](images/Pasted%20image%2020261028174047.png)

In the created file we see a lot of payloads and some obfuscated code at the end, so let's inspect it.

![source.py — obfuscated payloads](images/Pasted%20image%2020261028174920.png)

Let's unwind the obfuscation step by step:

1. Start from the visible `b64decode()` string and hope it decodes to `eval` / `compile` / `exec`, so we understand how execution works here.
2. Decoding it gives us **ROT13**, which doesn't immediately help — so let's look at the mess a bit closer.
3. We spot an `.exec` part. Replacing it with `.print` gives us `<code object <module> at 0x000002402E40B4E0, file "<string>", line 1>`. Not super useful yet — we *could* inspect its `co_consts` now, but let's first see if we can go deeper without it.
4. After a couple more arrays we hit a `.loads` string, which tells us the **marshal** library is in use. That means we can cut out a big part of the deobfuscation chain, which helps a lot.
5. At this point our only real option is to load `marshal.loads(...)` into a variable and analyze it via `co_consts`, which should give us some information.

And here's the result:

```python
(0, None, ('Thread',), ('wintypes',), ('PoolManager', 'HTTPResponse', 'disable_warnings'), <code object Settings at 0x0000019E7D2D58C0, file "<string>", line 27>, 'Settings', '_MEIPASS', -11, 7, '\x1b[1;36m%(funcName)s\x1b[0m:\x1b[1;33m%(levelname)7s\x1b[0m:%(message)s', ('format',), True, 'Blank Grabber', <code object VmProtect at 0x0000019E7CDE6BF0, file "<string>", line 73>, 'VmProtect', <code object Errors at 0x0000019E7D4CC030, file "<string>", line 143>, 'Errors', <code object Tasks at 0x0000019E7D4C8290, file "<string>", line 163>, 'Tasks', <code object Syscalls at 0x0000019E7CE128E0, file "<string>", line 176>, 'Syscalls', <code object Utility at 0x0000019E7D2A5AA0, file "<string>", line 242>, 'Utility', <code object Browsers at 0x0000019E7D0A0FF0, file "<string>", line 447>, 'Browsers', <code object Discord at 0x0000019E7D368020, file "<string>", line 660>, 'Discord', <code object BlankGrabber at 0x0000019E7D30BF60, file "<string>", line 926>, 'BlankGrabber', 'nt', 'Process started', 'Admin privileges not available', 1, '--nouacbypass', 'Trying to bypass UAC (Application will restart)', 'Failed to bypass UAC', 'Showing UAC prompt', 'Showing UAC prompt to user (Application will restart)', 'Trying to create mutex', 'Mutex already exists, exiting', 'Trying to exclude the file from Windows defender', 'Trying to disable defender', 'bound.blank', 'Trying to extract bound file', 'temp', 'bound.exe', 'Old bound file found, removing it', 'rb', -1, 'wb', 'Trying to exclude bound file from defender', 'Starting bound file', 'start bound.exe', ('shell', 'cwd', 'creationflags'), 'Showing fake error popup', '"', '\\x22', "'", 2, 'mshta "javascript:var sh=new ActiveXObject(\'WScript.Shell\'); sh.Popup(\'{}\', 0, \'{}\', {}+16);close()"', ('shell', 'creationflags'), 'Hiding the file', 'Deleting the file', 'Trying to put the file in startup', 'Excluding the file from Windows defender in startup', 'Failed to put the file in startup', 'Checking internet connection', 'Internet connection available, starting stealer (things will be running in parallel)', 'Stealer finished its work', 'Internet connection not found, retrying in 10 seconds', 10, ('exc_info',), 'There was an error, retrying after 10 minutes', 600, 'Process ended')
```

Here we see several code objects, which means we can pull their `co_consts` too. We're not interested in `Utility` / `Browsers` / `Discord` / `Syscalls` / `Errors` / `VmProtect` — we're here for the credentials / exfil config, so only `Settings` and `BlankGrabber` are interesting (by name, those are the ones likely to hold the creds). If they don't, we fall back to the "boring" ones.

Let's start with **`Settings`** (index 5):

```python
('Settings', 1, '[REDACTED — base64 of bot_token:owner_id]', 'WnJuYXFFZFVkN0E5MTZ0NQ==', '', 'true', 'MTIz', ('', '', '0'), None)
```

Here we have something that looks like base64, so let's try decoding it. The first string decodes to a **Telegram bot token + owner ID**:

```
[REDACTED_BOT_TOKEN]:7213984680
```

Where the first part is the **bot token** (redacted here — see note below) and `7213984680` is the **owner's Telegram ID** (the account the stolen data is exfiltrated to). With the full token we’d have significant control over the bot — but **not** the ability to delete it, since that can only be done by the owner through BotFather. So all we can really do is gently ask the owner to remove it. Some people just spam the bot until they get a deletion or a token change, but that isn’t morally right (and legally questionable).

> 🔒 **Responsible-disclosure note:** the **bot token is redacted** on purpose — it's a live credential, and publishing it would let anyone hijack/abuse the bot. The **owner Telegram ID is kept** intentionally: it's the key IOC of this campaign and is trivially recoverable from the sample anyway, so it's the piece that actually belongs in the write-up.

---

Thanks for reading this write-up! Hope you found it useful. The original lives on my GitHub — <https://github.com/ske8ter> — so you can always find it there.
