#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PolyMorpher: Модуль для полиморфной трансформации исходного кода.

Этот модуль предоставляет функциональность для изменения структуры 
исходного кода, сохраняя его функциональность, но изменяя сигнатуру, 
что затрудняет обнаружение сигнатурными методами анализа.
"""

import ast
import random
import string
import re
import os
import sys
import tempfile
import subprocess
from typing import List, Dict, Any, Tuple, Optional, Union

class PolyMorpher:
    """Класс для полиморфной трансформации исходного кода."""
    
    def __init__(self, randomization_level: int = 3):
        """
        Инициализация модуля полиморфной трансформации.
        
        Args:
            randomization_level: Уровень рандомизации от 1 до 5, где 5 - максимальная.
        """
        self.randomization_level = min(max(randomization_level, 1), 5)
        self.transformations = [
            self._rename_variables,
            self._add_junk_code,
            self._reorder_functions,
            self._modify_control_flow,
            self._encrypt_strings
        ]
    
    def transform_code(self, code: str) -> str:
        """
        Применяет полиморфную трансформацию к коду.
        
        Args:
            code: Исходный код для трансформации.
            
        Returns:
            Трансформированный код.
        """
        # Проверяем, что код синтаксически корректен
        try:
            ast.parse(code)
        except SyntaxError as e:
            raise ValueError(f"Синтаксическая ошибка в коде: {e}")
        
        transformed_code = code
        
        # Применяем количество трансформаций в зависимости от уровня рандомизации
        transforms_to_apply = random.sample(
            self.transformations, 
            min(self.randomization_level, len(self.transformations))
        )
        
        for transform in transforms_to_apply:
            transformed_code = transform(transformed_code)
        
        return transformed_code
    
    def _rename_variables(self, code: str) -> str:
        """Переименовывает переменные в коде для изменения сигнатуры."""
        tree = ast.parse(code)
        
        # Словарь для отслеживания замен имен
        rename_map = {}
        
        # Генератор новых имен
        def get_new_name():
            length = random.randint(5, 10)
            return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))
        
        # Трансформер AST для переименования переменных
        class VariableRenamer(ast.NodeTransformer):
            def visit_Name(self, node):
                if isinstance(node.ctx, ast.Store) and node.id not in rename_map:
                    # Не переименовываем специальные имена и встроенные функции
                    if not (node.id.startswith('__') or node.id in dir(__builtins__)):
                        rename_map[node.id] = get_new_name()
                
                if node.id in rename_map:
                    node.id = rename_map[node.id]
                return node
        
        # Применяем трансформер
        tree = VariableRenamer().visit(tree)
        ast.fix_missing_locations(tree)
        return ast.unparse(tree)
    
    def _add_junk_code(self, code: str) -> str:
        """Добавляет безвредный код, который не влияет на функциональность."""
        tree = ast.parse(code)
        
        # Генератор мусорного кода
        def generate_junk_stmt():
            junk_types = [
                # Тривиальное присваивание
                ast.Assign(
                    targets=[ast.Name(id=f"_junk_{random.randint(1000, 9999)}", ctx=ast.Store())],
                    value=ast.Constant(value=random.randint(1, 100))
                ),
                # Условие, которое всегда ложно
                ast.If(
                    test=ast.Compare(
                        left=ast.Constant(value=1),
                        ops=[ast.Eq()],
                        comparators=[ast.Constant(value=2)]
                    ),
                    body=[ast.Pass()],
                    orelse=[]
                ),
                # Безвредный цикл
                ast.For(
                    target=ast.Name(id=f"_j_{random.randint(1000, 9999)}", ctx=ast.Store()),
                    iter=ast.List(elts=[]),
                    body=[ast.Pass()],
                    orelse=[]
                )
            ]
            return random.choice(junk_types)
        
        # Трансформер AST для добавления мусорного кода
        class JunkInserter(ast.NodeTransformer):
            def visit_Module(self, node):
                # Добавляем мусор в начало модуля
                junk_count = random.randint(1, 3)
                for _ in range(junk_count):
                    node.body.insert(0, generate_junk_stmt())
                return node
                
            def visit_FunctionDef(self, node):
                # Пропускаем некоторые функции
                if random.random() < 0.7:
                    # Добавляем мусор в начало функции
                    junk_count = random.randint(1, 2)
                    for i in range(junk_count):
                        node.body.insert(i, generate_junk_stmt())
                    
                    # Добавляем мусор в произвольные места функции
                    if len(node.body) > 2 and random.random() < 0.5:
                        pos = random.randint(1, len(node.body) - 1)
                        node.body.insert(pos, generate_junk_stmt())
                
                self.generic_visit(node)
                return node
        
        # Применяем трансформер
        tree = JunkInserter().visit(tree)
        ast.fix_missing_locations(tree)
        return ast.unparse(tree)
    
    def _reorder_functions(self, code: str) -> str:
        """Изменяет порядок определений функций в коде."""
        tree = ast.parse(code)
        
        # Собираем все функции на верхнем уровне
        top_level_funcs = []
        other_nodes = []
        
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                top_level_funcs.append(node)
            else:
                other_nodes.append(node)
        
        # Перемешиваем функции
        if len(top_level_funcs) > 1:
            random.shuffle(top_level_funcs)
        
        # Собираем обратно
        tree.body = other_nodes + top_level_funcs
        
        return ast.unparse(tree)
    
    def _modify_control_flow(self, code: str) -> str:
        """Модифицирует структуру управления потоком выполнения."""
        tree = ast.parse(code)
        
        # Трансформер AST для изменения управления потоком
        class ControlFlowModifier(ast.NodeTransformer):
            def visit_If(self, node):
                # Посещаем дочерние узлы сначала
                self.generic_visit(node)
                
                # Преобразуем if x: A else: B в 
                # if x: A elif not x: B
                if node.orelse and random.random() < 0.5:
                    # Создаем условие "not x"
                    not_test = ast.UnaryOp(
                        op=ast.Not(),
                        operand=node.test
                    )
                    
                    # Преобразуем блок else в elif
                    elif_branch = ast.If(
                        test=not_test,
                        body=node.orelse,
                        orelse=[]
                    )
                    
                    # Убираем блок else и добавляем его как вложенный if
                    node.orelse = []
                    node.body.append(elif_branch)
                
                return node
                
            def visit_For(self, node):
                # Посещаем дочерние узлы сначала
                self.generic_visit(node)
                
                # Преобразуем for в эквивалентную конструкцию с while
                # только если нет else и вероятность 30%
                if not node.orelse and random.random() < 0.3:
                    # Создаем временную переменную для итератора
                    iter_var = f"_iter_{random.randint(1000, 9999)}"
                    
                    # Присваивание итератора: _iter = iter(x)
                    iter_assign = ast.Assign(
                        targets=[ast.Name(id=iter_var, ctx=ast.Store())],
                        value=ast.Call(
                            func=ast.Name(id='iter', ctx=ast.Load()),
                            args=[node.iter],
                            keywords=[]
                        )
                    )
                    
                    # Создаем бесконечный цикл с try-except для StopIteration
                    try_body = [
                        # target = next(_iter)
                        ast.Assign(
                            targets=[node.target],
                            value=ast.Call(
                                func=ast.Name(id='next', ctx=ast.Load()),
                                args=[ast.Name(id=iter_var, ctx=ast.Load())],
                                keywords=[]
                            )
                        )
                    ] + node.body
                    
                    except_handler = ast.ExceptHandler(
                        type=ast.Name(id='StopIteration', ctx=ast.Load()),
                        name=None,
                        body=[ast.Break()]
                    )
                    
                    while_body = [
                        ast.Try(
                            body=try_body,
                            handlers=[except_handler],
                            orelse=[],
                            finalbody=[]
                        )
                    ]
                    
                    # Создаем цикл while True:
                    while_loop = ast.While(
                        test=ast.Constant(value=True),
                        body=while_body,
                        orelse=[]
                    )
                    
                    # Возвращаем последовательность: назначение итератора + while
                    return [iter_assign, while_loop]
                
                return node
        
        # Применяем трансформер
        tree = ControlFlowModifier().visit(tree)
        ast.fix_missing_locations(tree)
        
        try:
            return ast.unparse(tree)
        except (TypeError, ValueError):
            # Если произошла ошибка при unparsing, возвращаем исходный код
            return code
    
    def _encrypt_strings(self, code: str) -> str:
        """Шифрует строковые литералы в коде."""
        tree = ast.parse(code)
        
        # Простая функция шифрования (просто для демонстрации)
        def simple_encrypt(s):
            # XOR с случайным ключом
            key = random.randint(1, 255)
            encrypted = bytes([ord(c) ^ key for c in s])
            return key, encrypted
            
        # Функция для генерации кода расшифровки
        def generate_decrypt_code(key, encrypted):
            # Представление байтов в виде списка чисел
            bytes_repr = ", ".join(str(b) for b in encrypted)
            
            # Генерируем код для расшифровки
            decrypt_code = f"""
            (lambda k, e: ''.join(chr(b ^ k) for b in e))({key}, bytes([{bytes_repr}]))
            """
            return decrypt_code.strip()
        
        # Трансформер AST для шифрования строк
        class StringEncrypter(ast.NodeTransformer):
            def visit_Constant(self, node):
                if isinstance(node.value, str) and node.value and random.random() < 0.7:
                    # Не шифруем пустые строки или документацию
                    if not node.value.strip() or (hasattr(node, 'parent') and 
                                                isinstance(node.parent, ast.Expr) and 
                                                node.parent.lineno == 1):
                        return node
                    
                    # Шифруем строку
                    key, encrypted = simple_encrypt(node.value)
                    
                    # Создаем выражение для расшифровки строки
                    decrypt_expr = ast.parse(generate_decrypt_code(key, encrypted)).body[0].value
                    
                    return decrypt_expr
                return node
        
        # Добавляем родительские ссылки для узлов
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                child.parent = node
        
        # Применяем трансформер
        tree = StringEncrypter().visit(tree)
        ast.fix_missing_locations(tree)
        
        try:
            return ast.unparse(tree)
        except (TypeError, ValueError):
            # Если произошла ошибка при unparsing, возвращаем исходный код
            return code
            
    def execute_code(self, code: str, as_file: bool = True) -> Tuple[int, str, str]:
        """
        Выполняет код и возвращает результат выполнения.
        
        Args:
            code: Код для выполнения.
            as_file: Если True, код сохраняется во временный файл и выполняется.
                    Если False, код выполняется через stdin.
                    
        Returns:
            Кортеж из (код_возврата, stdout, stderr)
        """
        if as_file:
            # Создаем временный файл
            with tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False) as f:
                f.write(code)
                temp_file = f.name
            
            try:
                # Выполняем как файл
                proc = subprocess.Popen(
                    [sys.executable, temp_file],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = proc.communicate()
                return proc.returncode, stdout, stderr
            finally:
                # Удаляем временный файл
                os.unlink(temp_file)
        else:
            # Выполняем через stdin
            proc = subprocess.Popen(
                [sys.executable, '-'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = proc.communicate(input=code)
            return proc.returncode, stdout, stderr
    
    def compare_execution(self, original_code: str, transformed_code: str) -> bool:
        """
        Сравнивает результаты выполнения оригинального и трансформированного кода.
        
        Args:
            original_code: Оригинальный код.
            transformed_code: Трансформированный код.
            
        Returns:
            True, если результаты совпадают, иначе False.
        """
        # Выполняем оба кода
        orig_ret, orig_out, orig_err = self.execute_code(original_code)
        trans_ret, trans_out, trans_err = self.execute_code(transformed_code)
        
        # Проверяем совпадение кодов возврата и вывода stdout
        return orig_ret == trans_ret and orig_out == trans_out


# Пример использования, если файл запущен напрямую
if __name__ == "__main__":
    test_code = """
def factorial(n):
    if n == 0 or n == 1:
        return 1
    else:
        return n * factorial(n-1)

print("Factorial of 5:", factorial(5))
"""
    
    morpher = PolyMorpher(randomization_level=3)
    transformed = morpher.transform_code(test_code)
    
    print("Original code:")
    print(test_code)
    print("\nTransformed code:")
    print(transformed)
    
    print("\nExecuting original code:")
    orig_ret, orig_out, orig_err = morpher.execute_code(test_code)
    print(f"Return code: {orig_ret}")
    print(f"Output: {orig_out}")
    if orig_err: print(f"Error: {orig_err}")
    
    print("\nExecuting transformed code:")
    trans_ret, trans_out, trans_err = morpher.execute_code(transformed)
    print(f"Return code: {trans_ret}")
    print(f"Output: {trans_out}")
    if trans_err: print(f"Error: {trans_err}")
    
    print(f"\nResults match: {morpher.compare_execution(test_code, transformed)}") 