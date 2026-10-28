package br.com.oficina.authorizer.infrastructure;

import com.nimbusds.jose.util.JSONObjectUtils;
import java.io.PrintStream;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Log JSON de uma linha por evento, sem framework. O CloudWatch carimba o instante.
 *
 * <p>Regra do chamador: <b>nunca</b> passar o token nem o header {@code Authorization} — só o motivo
 * da recusa, o papel e identificadores.</p>
 */
public final class StructuredLogger {

    private final PrintStream out;

    public StructuredLogger(PrintStream out) {
        this.out = out;
    }

    public void info(String event, Map<String, ?> fields) {
        write("INFO", event, fields);
    }

    public void warn(String event, Map<String, ?> fields) {
        write("WARN", event, fields);
    }

    public void error(String event, Map<String, ?> fields) {
        write("ERROR", event, fields);
    }

    private void write(String level, String event, Map<String, ?> fields) {
        Map<String, Object> line = new LinkedHashMap<>();
        line.put("level", level);
        line.put("event", event);
        line.putAll(fields);
        out.println(JSONObjectUtils.toJSONString(line));
    }
}
