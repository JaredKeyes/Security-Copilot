FROM public.ecr.aws/lambda/python:3.12

COPY requirements-serving.txt .
RUN pip install --no-cache-dir -r requirements-serving.txt

COPY src/llm/client.py                      src/llm/client.py
COPY src/llm/answer_question.py             src/llm/answer_question.py
COPY src/retrieval/query_vector_index.py    src/retrieval/query_vector_index.py
COPY src/serving/                           src/serving/

COPY data/vector_store/                     data/vector_store/

CMD ["src.serving.app.handler"]