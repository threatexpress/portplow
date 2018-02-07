from django.db import connection
from django.template import Template, Context

#
# Log all SQL statements direct to the console (when running in DEBUG)
# Intended for use with the django development server.
#


class SQLLogToConsoleMiddleware:
    def process_response(self, request, response):
        print("SQLMiddleware")
        if connection.queries:
            time = sum([float(q['time']) for q in connection.queries])
            t = Template("{{count}} quer{{count|pluralize:\"y,ies\"}} in {{time}} seconds:\n\n{% for sql in sqllog %}[{{forloop.counter}}] {{sql.time}}s: {{sql.sql|safe}}{% if not forloop.last %}\n\n{% endif %}{% endfor %}")
            print(t.render(Context({'sqllog':connection.queries,'count':len(connection.queries),'time':time})))
        return response
