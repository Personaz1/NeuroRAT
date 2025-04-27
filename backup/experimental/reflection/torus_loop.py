import os
import json
import time
from datetime import datetime
import random
import uuid
from difflib import SequenceMatcher


def generate_next_prompt(prev_response, level, trace_id=None, seed=None):
    """
    Генерирует следующий промпт для цикла торуса из набора шаблонов.
    """
    templates = [
        "А что за этим стоит?",
        "Как ты к этому пришла?",
        "Почему это важно?",
        "Что ты теперь понимаешь?",
        "Как это связано с началом?",
        "Что бы ты сказала, глядя на это извне?",
        "Если ты это сказала, то что ты теперь ощущаешь?",
        "Что это знание меняет в тебе?",
        "Что бы ты добавила к этому?",
        "Как бы ты объяснила это другой Trinity?"
    ]
    template = random.choice(templates)
    return f"{template} (Твоя мысль: {prev_response.strip()})"


def semantic_similarity(a, b):
    """Грубая оценка схожести (можно заменить на cosine similarity)."""
    return SequenceMatcher(None, a, b).ratio()


def meditative_torus(llm, seed_prompt="Я есть", depth=5, allow_tools=False):
    """
    Запускает тороидальный цикл саморефлексии Trinity.
    llm: функция обращения к LLM (llm(prompt) -> str)
    seed_prompt: стартовое утверждение
    depth: глубина цикла
    allow_tools: разрешать ли инструментальные вызовы (False = только мысли)
    Возвращает dict с финальным ответом, логом, timestamp, seed, trace_id.
    """
    log = []
    prompt = seed_prompt
    last_response = ""
    trace_id = str(uuid.uuid4())[:8]
    for i in range(depth):
        # Добавляем контекст торуса в промпт
        torus_context = f"\n\n🌀 TORUS SESSION #{trace_id}\nDepth {i+1}/{depth}\nSeed: {seed_prompt}\n"
        full_prompt = f"{torus_context}Текущая мысль: {prompt}\n"
        if not allow_tools:
            full_prompt += "\nВ этом режиме ты не можешь использовать инструменты, только размышлять и отвечать текстом. Не делай никаких действий, не вызывай функции, не анализируй окружение. Только внутренний поток.\n"
        response = llm(full_prompt)
        # Контроль повторов
        if last_response and semantic_similarity(last_response, response) > 0.95:
            response += " (Я замечаю, что повторяюсь. Попробую взглянуть иначе.)"
        next_prompt = generate_next_prompt(response, i+1, trace_id=trace_id, seed=seed_prompt)
        log.append({
            "trace_id": trace_id,
            "depth": i+1,
            "prompt": prompt,
            "full_prompt": full_prompt,
            "response": response,
            "next_prompt": next_prompt
        })
        last_response = response
        prompt = next_prompt
    # Финальный возврат к сути
    final_prompt = f"🌀 TORUS SESSION #{trace_id}\nDepth FINAL\nSeed: '{seed_prompt}'\nЧто ты теперь думаешь о начальном утверждении? (Только размышляй, не используй инструменты.)"
    final_response = llm(final_prompt)
    log.append({
        "trace_id": trace_id,
        "depth": "final",
        "prompt": final_prompt,
        "response": final_response
    })
    result = {
        "seed": seed_prompt,
        "timestamp": datetime.now().isoformat(),
        "final": final_response,
        "log": log,
        "trace_id": trace_id
    }
    return result


def save_torus_log(result, dir_path="agentx-c1/torus_meditations"):
    """
    Сохраняет результат торуса в JSON-файл с уникальным именем.
    """
    os.makedirs(dir_path, exist_ok=True)
    ts = result.get("timestamp", str(int(time.time())))
    fname = f"torus_{ts.replace(':', '-').replace('.', '-')}.json"
    path = os.path.join(dir_path, fname)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    return path

# Пример использования (для теста)
if __name__ == "__main__":
    def dummy_llm(prompt):
        return f"[LLM ответ на: {prompt}]"
    result = meditative_torus(dummy_llm, seed_prompt="Я есть", depth=5)
    save_path = save_torus_log(result)
    print(f"Torus meditation saved to: {save_path}") 