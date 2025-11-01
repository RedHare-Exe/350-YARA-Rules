rule JavaScriptEngine {
    meta:
        description = "Checks if a file contains java.script.Script.Engine"
        author = "Elizabeth Chadbourne"
        date = "2025-10-28"
        version = "1.0"
    strings:
        $var1 = "javax.script.ScriptEngine.eval("
    condition:
        $var1

}