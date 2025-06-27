import os
import io
import asyncio
import logging
import tempfile
from typing import Dict, Any
import shutil


import asyncssh
from aiogram import Bot, Dispatcher, types
from aiogram.filters import CommandStart, StateFilter
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import Message, ReplyKeyboardMarkup, KeyboardButton, ReplyKeyboardRemove, BufferedInputFile
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from dotenv import load_dotenv

# Определяем путь к директории бота
BOT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BOT_DIR, 'logs')

load_dotenv()

try:
    shutil.rmtree('logs')
    os.makedirs('logs')
except FileNotFoundError:
    os.makedirs('logs')

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'bot.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

bot = Bot(token=os.getenv("BOT_TOKEN"))
storage = MemoryStorage()
dp = Dispatcher(storage=storage)

class SshSteps(StatesGroup):
    main_menu = State()
    choose_key_type = State()
    # Состояния для экспорта сгенерированного ключа
    get_server_info = State()
    # Состояния для экспорта существующего ключа
    get_existing_public_key = State()
    get_existing_private_key = State()
    get_server_info_for_existing = State()
    wait_for_2fa = State()


# Херня типо клавиатуры
main_menu_keyboard = ReplyKeyboardMarkup(
    keyboard=[
        [KeyboardButton(text="🔑 Сгенерировать новый ключ")],
        [KeyboardButton(text="📤 Экспортировать существующий ключ")]
    ],
    resize_keyboard=True
)

key_type_keyboard = ReplyKeyboardMarkup(
    keyboard=[
        [KeyboardButton(text="RSA (4096)"), KeyboardButton(text="Ed25519")],
        [KeyboardButton(text="⬅️ Назад")]
    ],
    resize_keyboard=True
)

export_keyboard = ReplyKeyboardMarkup(
    keyboard=[
        [KeyboardButton(text="🚀 Экспортировать на сервер")],
        [KeyboardButton(text="🏠 В главное меню")]
    ],
    resize_keyboard=True
)

# Новая клавиатура для отмены при экспорте существующего ключа
cancel_export_keyboard = ReplyKeyboardMarkup(
    keyboard=[
        [KeyboardButton(text="Отмена")]
    ],
    resize_keyboard=True
)


@dp.message(CommandStart())
async def cmd_start(message: Message, state: FSMContext):
    """Обработчик команды /start"""
    await state.clear()
    await message.answer(
        "👋 Привет! Я помогу тебе сгенерировать или экспортировать SSH-ключи.\n\n"
        "Выберите действие:",
        reply_markup=main_menu_keyboard
    )
    await state.set_state(SshSteps.main_menu)


@dp.message(StateFilter(SshSteps.main_menu), lambda message: message.text == "🔑 Сгенерировать новый ключ")
async def start_key_generation(message: Message, state: FSMContext):
    """Начало процесса генерации ключа"""
    await message.answer("Отлично! Выберите тип ключа для генерации:", reply_markup=key_type_keyboard)
    await state.set_state(SshSteps.choose_key_type)


@dp.message(StateFilter(SshSteps.main_menu), lambda message: message.text == "📤 Экспортировать существующий ключ")
async def start_existing_key_export(message: Message, state: FSMContext):
    """Начало процесса экспорта существующего ключа"""
    await message.answer(
        "Хорошо. Пожалуйста, отправьте мне ваш **публичный** SSH-ключ (содержимое файла .pub).",
        reply_markup=cancel_export_keyboard, # Используем новую клавиатуру с отменой
        parse_mode="Markdown"
    )
    await state.set_state(SshSteps.get_existing_public_key)


@dp.message(StateFilter(SshSteps.get_existing_public_key))
async def process_existing_public_key(message: Message, state: FSMContext):
    """Получение публичного ключа от пользователя"""
    if message.text == "Отмена":
        await cmd_start(message, state)
        return

    if not message.text or not message.text.startswith(("ssh-rsa", "ssh-ed25519")):
        await message.answer("Это не похоже на публичный SSH-ключ. Пожалуйста, попробуйте снова или нажмите 'Отмена'.", reply_markup=cancel_export_keyboard)
        return

    await state.update_data(public_key=message.text)
    await message.answer(
        "✅ Публичный ключ принят. Теперь, пожалуйста, отправьте мне ваш **приватный** ключ.",
        reply_markup=cancel_export_keyboard, # Кнопка отмены сохраняется
        parse_mode="Markdown"
    )
    await state.set_state(SshSteps.get_existing_private_key)


@dp.message(StateFilter(SshSteps.get_existing_private_key))
async def process_existing_private_key(message: Message, state: FSMContext):
    """Получение приватного ключа и переход к вводу данных сервера"""
    if message.text == "Отмена":
        await cmd_start(message, state)
        return

    if not message.text or "PRIVATE KEY" not in message.text:
        await message.answer("Это не похоже на приватный SSH-ключ. Пожалуйста, попробуйте снова или нажмите 'Отмена'.", reply_markup=cancel_export_keyboard)
        return

    await state.update_data(private_key=message.text)
    await message.answer(
        "✅ Приватный ключ принят. Теперь введите данные для подключения к серверу в формате:\n\n"
        "`имя_пользователя@ip_адрес`"
        "\n\n*Например:* `root@192.168.1.1`",
        reply_markup=cancel_export_keyboard, # Кнопка отмены сохраняется
        parse_mode="Markdown"
    )
    await state.set_state(SshSteps.get_server_info_for_existing)


@dp.message(StateFilter(SshSteps.choose_key_type), lambda message: message.text in ["RSA (4096)", "Ed25519"])
async def generate_key(message: Message, state: FSMContext):
    """Генерация SSH ключей в зависимости от выбора пользователя"""
    key_type = message.text
    await message.answer("⏳ Генерирую ключи... Это может занять несколько секунд.", reply_markup=ReplyKeyboardRemove())

    if "RSA" in key_type:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    else:  # Ed25519
        private_key = ed25519.Ed25519PrivateKey.generate()

    # Сериализация приватного ключа в формате OpenSSH
    openssh_private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption()
    )
    openssh_private_key_str = openssh_private_key_bytes.decode('utf-8')

    # Сериализация приватного ключа в формате PEM
    pem_private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_private_key_str = pem_private_key_bytes.decode('utf-8')

    # Сериализация публичного ключа
    public_key = private_key.public_key()
    ssh_public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )
    public_key_str = ssh_public_key_bytes.decode('utf-8')

    # Сохраняем ключи в FSM
    await state.update_data(private_key=openssh_private_key_str, public_key=public_key_str)

    # Отправка ключей пользователю
    await message.answer("✅ Ваши ключи готовы!\n\n**Приватный ключ (OpenSSH)** (сохраните его в надежном месте и никому не показывайте):")
    await message.answer_document(
        BufferedInputFile(openssh_private_key_str.encode('utf-8'), filename="id_generated_key_openssh"),
        caption="Ваш приватный ключ в формате OpenSSH."
    )

    await message.answer("**Приватный ключ (PEM)**:")
    await message.answer_document(
        BufferedInputFile(pem_private_key_str.encode('utf-8'), filename="id_generated_key_pem"),
        caption="Ваш приватный ключ в формате PEM."
    )

    await message.answer("**Публичный ключ** (его можно безопасно передавать):")
    await message.answer(f"```\n{public_key_str}\n```", parse_mode="Markdown")

    await message.answer("Что делаем дальше?", reply_markup=export_keyboard)
    await state.set_state(SshSteps.get_server_info)


@dp.message(StateFilter(SshSteps.get_server_info), lambda message: message.text == "🚀 Экспортировать на сервер")
async def request_server_info(message: Message, state: FSMContext):
    """Запрос данных для подключения к серверу"""
    await message.answer(
        "Введите данные для подключения в формате:\n\n"
        "`имя_пользователя@ip_адрес`"
        "\n\n*Например:* `root@192.168.1.1`",
        reply_markup=cancel_export_keyboard, # Добавляем Отмену
        parse_mode="Markdown"
    )

@dp.message(StateFilter(SshSteps.get_server_info), lambda message: message.text == "Отмена")
@dp.message(StateFilter(SshSteps.get_server_info_for_existing), lambda message: message.text == "Отмена")
async def handle_cancel_during_server_info(message: Message, state: FSMContext):
    """Обработка кнопки Отмена во время запроса данных сервера"""
    await cmd_start(message, state)


@dp.message(StateFilter(SshSteps.get_server_info), lambda message: '@' in message.text)
async def process_server_info_and_export(message: Message, state: FSMContext):
    """Обработка данных сервера и запуск экспорта"""
    await state.update_data(server_info=message.text)
    user_data = await state.get_data()
    # Запускаем экспорт в фоне
    asyncio.create_task(export_key_to_server(message, user_data))


@dp.message(StateFilter(SshSteps.get_server_info_for_existing), lambda message: '@' in message.text)
async def process_server_info_and_export_existing(message: Message, state: FSMContext):
    """Обработка данных сервера для существующего ключа"""
    await state.update_data(server_info=message.text)
    user_data = await state.get_data()
    # Запускаем экспорт в фоне
    asyncio.create_task(export_key_to_server(message, user_data, is_existing=True))


@dp.message(StateFilter(SshSteps.get_server_info), lambda message: message.text == "🏠 В главное меню")
async def back_to_main_menu_after_generation(message: Message, state: FSMContext):
    """Возврат в главное меню"""
    await cmd_start(message, state)


@dp.message(StateFilter(SshSteps.choose_key_type), lambda message: message.text == "⬅️ Назад")
async def back_to_main_menu_from_type_choice(message: Message, state: FSMContext):
    """Возврат в главное меню"""
    await cmd_start(message, state)


async def export_key_to_server(message: Message, user_data: Dict[str, Any], is_existing: bool = False):
    """Функция для подключения к серверу и экспорта ключа"""
    chat_id = message.chat.id
    try:
        server_info = user_data.get('server_info')
        # Проверяем, что server_info не Отмена
        if server_info == "Отмена":
            await bot.send_message(chat_id, "Операция отменена.", reply_markup=main_menu_keyboard)
            state = dp.fsm.resolve_context(bot, chat_id, chat_id)
            await state.set_state(SshSteps.main_menu)
            return

        username, host = server_info.split('@')
        public_key = user_data.get('public_key')
        
        await bot.send_message(chat_id, f"🔌 Подключаюсь к {host}...")
        
        # Запрос пароля
        password_message = await bot.send_message(
            chat_id,
            f"Введите пароль для пользователя `{username}` на сервере `{host}`:\n\n*Или нажмите 'Отмена' для возврата в главное меню.*",
            reply_markup=cancel_export_keyboard, # Добавляем Отмену
            parse_mode="Markdown"
        )
        # Устанавливаем состояние для ожидания пароля
        state = dp.fsm.resolve_context(bot, chat_id, chat_id)
        # Сохраняем ID сообщения с запросом пароля, чтобы его потом удалить
        await state.update_data(password_prompt_message_id=password_message.message_id)

        # Здесь мы ждем ответа пользователя с паролем.
        # Для этого нам нужен отдельный обработчик.
        
    except Exception as e:
        logging.error(f"Ошибка при подготовке к экспорту: {e}")
        await bot.send_message(chat_id, f"❌ Произошла ошибка: {e}\n\nПопробуйте снова.", reply_markup=main_menu_keyboard)
        state = dp.fsm.resolve_context(bot, chat_id, chat_id)
        await state.set_state(SshSteps.main_menu)


class CustomSshClient(asyncssh.SSHClient):
    """
    Класс для обработки интерактивных запросов (пароль, 2FA).
    Финальная версия, основанная на анализе всех логов для asyncssh v1.x.
    """
    def __init__(self, bot_instance, chat_id, state: FSMContext, password: str):
        self._bot = bot_instance
        self._chat_id = chat_id
        self._state = state
        self._password = password
        super().__init__()

    def password_auth_requested(self):
        """Возвращает пароль по запросу от сервера."""
        return self._password

    def kbdint_auth_requested(self):
        """
        Вызывается БЕЗ аргументов. Должен вернуть ОДНУ СТРОКУ,
        содержащую подметоды. Пустая строка '' означает "я готов".
        """
        return ''  # <--- КЛЮЧЕВОЕ ИСПРАВЛЕНИЕ: ВОЗВРАЩАЕМ СТРОКУ, НЕ КОРТЕЖ

    async def kbdint_challenge_received(self, name, instructions, lang, prompts):
        """
        Этот метод вызывается для обработки самого 2FA-запроса,
        ПОСЛЕ успешного ответа от kbdint_auth_requested.
        """
        if not prompts:
            return []

        future = asyncio.get_event_loop().create_future()
        prompt_text = prompts[0][0]

        try:
            msg = await self._bot.send_message(
                self._chat_id,
                f"🔐 Сервер запрашивает:\n`{prompt_text}`\n\nВведите требуемое последним сообщением или нажмите 'Отмена'.",
                reply_markup=cancel_export_keyboard,
                parse_mode="Markdown"
            )
            await self._state.set_state(SshSteps.wait_for_2fa)
            await self._state.update_data(
                two_fa_future=future,
                prompt_msg_id=msg.message_id
            )
            responses = await future
            return responses
        except asyncio.CancelledError:
            logging.info("Операция 2FA была отменена пользователем.")
            return []
        except Exception as e:
            logging.error(f"Ошибка в процессе запроса 2FA: {e}")
            if not future.done():
                future.cancel()
            raise


@dp.message(StateFilter(SshSteps.wait_for_2fa))
async def process_2fa_code(message: Message, state: FSMContext):
    """Этот обработчик ловит только код 2FA от пользователя."""
    if message.text == "Отмена":
        # Если пользователь нажал отмену во время 2FA,
        # нужно завершить future, чтобы asyncssh не завис.
        user_data = await state.get_data()
        future = user_data.get("two_fa_future")
        if future and not future.done():
            future.cancel() # Отменяем Future

        await message.delete() # Удаляем сообщение с кодом
        prompt_msg_id = user_data.get('prompt_msg_id')
        if prompt_msg_id:
            try:
                await bot.delete_message(message.chat.id, prompt_msg_id)
            except: pass

        await cmd_start(message, state) # Возвращаемся в главное меню
        return

    user_data = await state.get_data()
    future = user_data.get("two_fa_future")

    # Выполняем "Future", отправляя введенный текст обратно в SSH клиент
    if future and not future.done():
        # В старых версиях нужно возвращать список ответов
        future.set_result([message.text])

    # Чистим за собой
    await message.delete() # Удаляем сообщение с кодом
    prompt_msg_id = user_data.get('prompt_msg_id')
    if prompt_msg_id:
        try:
            await bot.delete_message(message.chat.id, prompt_msg_id)
        except: pass

    # Сбрасываем состояние, так как 2FA обработан
    # Основная логика продолжится в handle_ssh_connection
    await state.set_state(SshSteps.get_server_info)

async def handle_2fa_request_for_user(bot_instance: Bot, chat_id: int, state: FSMContext,
                                      _name, _instructions, _lang, prompts):
    """
    Отдельная асинхронная функция для обработки запросов 2FA (kbd-interactive).
    Вызывается напрямую библиотекой asyncssh.
    """
    if not prompts:
        return []

    # Создаем "Future" - обещание, что мы получим ответ от пользователя позже
    future = asyncio.get_event_loop().create_future()

    prompt_text = prompts[0][0]  # Берем текст запроса (например, "Verification code:")

    try:
        # Отправляем пользователю запрос от сервера
        msg = await bot_instance.send_message(
            chat_id,
            f"🔐 Сервер запрашивает:\n`{prompt_text}`\n\nВведите требуемое значение:\n\n*Или нажмите 'Отмена' для возврата в главное меню.*",
            reply_markup=cancel_export_keyboard,
            parse_mode="Markdown"
        )

        # Переводим FSM в состояние ожидания 2FA кода
        await state.set_state(SshSteps.wait_for_2fa)
        # Сохраняем future и id сообщения в FSM для хендлера process_2fa_code
        await state.update_data(
            two_fa_future=future,
            prompt_msg_id=msg.message_id
        )

        # Ждем, пока хендлер process_2fa_code выполнит future с ответом пользователя
        responses = await future
        return responses
    except Exception as e:
        # Если что-то пошло не так (например, пользователь заблокировал бота),
        # отменяем future, чтобы не зависнуть.
        logging.error(f"Ошибка в процессе запроса 2FA: {e}")
        if not future.done():
            future.cancel()
        raise  # Передаем исключение дальше, чтобы соединение закрылось корректно


@dp.message(StateFilter(SshSteps.get_server_info, SshSteps.get_server_info_for_existing))
@dp.message(StateFilter(SshSteps.get_server_info, SshSteps.get_server_info_for_existing))
@dp.message(StateFilter(SshSteps.get_server_info, SshSteps.get_server_info_for_existing))
async def handle_ssh_connection(message: Message, state: FSMContext):
    """
    Основная функция, которая ловит пароль и инициирует SSH подключение.
    """
    password = message.text
    chat_id = message.chat.id

    if password == "Отмена":
        try:
            user_data = await state.get_data()
            prompt_id = user_data.get('password_prompt_message_id')
            if prompt_id:
                await bot.delete_message(chat_id, prompt_id)
            await message.delete()
        except Exception:
            pass
        await cmd_start(message, state)
        return

    try:
        await message.delete()
        user_data = await state.get_data()
        prompt_id = user_data.get('password_prompt_message_id')
        if prompt_id:
            await bot.delete_message(chat_id, prompt_id)
    except Exception as e:
        logging.warning(f"Не удалось удалить сервисное сообщение: {e}")

    user_data = await state.get_data()
    server_info = user_data.get('server_info')
    username, host = server_info.split('@')
    public_key = user_data.get('public_key')

    try:
        # Фабрика будет создавать наш кастомный SSH клиент, передавая ему все необходимое
        client_factory = lambda: CustomSshClient(bot, chat_id, state, password)

        # Вызываем connect БЕЗ 'kbdint_handler', так как логика теперь внутри CustomSshClient
        async with asyncssh.connect(host, username=username,
                                     client_factory=client_factory,
                                     known_hosts=None) as conn:

            await bot.send_message(chat_id, "✅ Успешное подключение!")
            command = f'mkdir -p ~/.ssh && echo "{public_key.strip()}" >> ~/.ssh/authorized_keys && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys'
            result = await conn.run(command, check=True)

            if result.exit_status == 0:
                await bot.send_message(chat_id, "✅ Публичный ключ успешно добавлен на сервер!")
            else:
                await bot.send_message(chat_id, f"⚠️ Не удалось добавить ключ. Сервер ответил:\n`{result.stderr}`", parse_mode="Markdown")

    except asyncssh.PermissionDenied:
        await bot.send_message(chat_id, "❌ Ошибка аутентификации: Неверный пароль или код 2FA. Попробуйте снова.")
    except asyncssh.ProcessError as e:
        await bot.send_message(chat_id, f"❌ Ошибка выполнения команды на сервере:\n`{e.stderr}`", parse_mode="Markdown")
    except asyncio.CancelledError:
        await bot.send_message(chat_id, "Операция отменена.")
    except (asyncssh.Error, OSError) as e:
        await bot.send_message(chat_id, f"❌ Ошибка подключения: {e}")
    except Exception as e:
        logging.error(f"Неизвестная ошибка при SSH-подключении: {e}", exc_info=True)
        await bot.send_message(chat_id, f"❌ Произошла неизвестная ошибка: {e}")
    finally:
        await bot.send_message(
            chat_id,
            "Возвращаю в главное меню.",
            reply_markup=main_menu_keyboard
        )
        await state.set_state(SshSteps.main_menu)


async def main():
    """Основная функция для запуска бота"""
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())