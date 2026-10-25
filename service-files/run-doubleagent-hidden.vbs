Set shell = CreateObject("WScript.Shell")
command = """" & "E:\DoubleAgent\target\release\doubleagent.exe" & """ daemon"
shell.Run command, 0, False
