FROM public.ecr.aws/lambda/python3.12

COPY requirements-serving.txt .
RUN pip install --no-cache-dir -r requirements-serving.txt

COPY src/llm/client.py      src/llm/client.py
COPY src/llm/answer_question.py src/llm/answer_question.py
COPY src/serving/           src/serving/
COPY src/__init__.py        src/__init__.py 2>/dev/null || true

CMD ["src.serving.app.handler"]