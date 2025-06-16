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

# Загружаем переменные окружения из .env файла
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

# Инициализация бота и диспетчера
bot = Bot(token=os.getenv("BOT_TOKEN"))
storage = MemoryStorage()
dp = Dispatcher(storage=storage)

# --- Состояния для машины состояний (FSM) ---
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


# --- Клавиатуры ---
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


# --- Обработчики команд ---

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
        reply_markup=ReplyKeyboardRemove(),
        parse_mode="Markdown"
    )
    await state.set_state(SshSteps.get_existing_public_key)


@dp.message(StateFilter(SshSteps.get_existing_public_key))
async def process_existing_public_key(message: Message, state: FSMContext):
    """Получение публичного ключа от пользователя"""
    if not message.text or not message.text.startswith(("ssh-rsa", "ssh-ed25519")):
        await message.answer("Это не похоже на публичный SSH-ключ. Пожалуйста, попробуйте снова.")
        return

    await state.update_data(public_key=message.text)
    await message.answer(
        "✅ Публичный ключ принят. Теперь, пожалуйста, отправьте мне ваш **приватный** ключ.",
        parse_mode="Markdown"
    )
    await state.set_state(SshSteps.get_existing_private_key)


@dp.message(StateFilter(SshSteps.get_existing_private_key))
async def process_existing_private_key(message: Message, state: FSMContext):
    """Получение приватного ключа и переход к вводу данных сервера"""
    if not message.text or "PRIVATE KEY" not in message.text:
        await message.answer("Это не похоже на приватный SSH-ключ. Пожалуйста, попробуйте снова.")
        return

    await state.update_data(private_key=message.text)
    await message.answer(
        "✅ Приватный ключ принят. Теперь введите данные для подключения к серверу в формате:\n\n"
        "`имя_пользователя@ip_адрес`"
        "\n\n*Например:* `root@192.168.1.1`",
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

    # Сериализация приватного ключа
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Сериализация публичного ключа
    public_key = private_key.public_key()
    ssh_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )

    private_key_str = pem.decode('utf-8')
    public_key_str = ssh_public_key.decode('utf-8')

    # Сохраняем ключи в FSM
    await state.update_data(private_key=private_key_str, public_key=public_key_str)

    # Отправка ключей пользователю
    await message.answer("✅ Ваши ключи готовы!\n\n**Приватный ключ** (сохраните его в надежном месте и никому не показывайте):")
    await message.answer_document(
        BufferedInputFile(private_key_str.encode('utf-8'), filename="id_generated_key"),
        caption="Ваш приватный ключ."
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
        reply_markup=ReplyKeyboardRemove(),
        parse_mode="Markdown"
    )


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

# --- Логика SSH ---

async def export_key_to_server(message: Message, user_data: Dict[str, Any], is_existing: bool = False):
    """Функция для подключения к серверу и экспорта ключа"""
    chat_id = message.chat.id
    try:
        server_info = user_data.get('server_info')
        username, host = server_info.split('@')
        public_key = user_data.get('public_key')
        
        await bot.send_message(chat_id, f"🔌 Подключаюсь к {host}...")
        
        # Запрос пароля
        password_message = await bot.send_message(
            chat_id,
            f"Введите пароль для пользователя `{username}` на сервере `{host}`:",
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


# --- НАЧАЛО БЛОКА НА ЗАМЕНУ ---

class CustomSshClient(asyncssh.SSHClient):
    """
    Класс для обработки интерактивных запросов (пароль, 2FA)
    для старых версий asyncssh (< 2.0).
    """
    def __init__(self, bot_instance, chat_id, state: FSMContext, password: str):
        self._bot = bot_instance
        self._chat_id = chat_id
        self._state = state
        self._password = password
        self._2fa_future = None

    def password_auth_requested(self):
        # Отвечаем на запрос пароля
        return self._password

    def kbdint_auth_requested(self, name, instructions, lang, prompts):
        # Этот метод вызывается, когда сервер запрашивает 2FA код
        # (keyboard-interactive authentication)
        if not prompts:
            return [] # Нечего запрашивать

        # Создаем "Future" - обещание, что мы получим ответ позже
        self._2fa_future = asyncio.get_event_loop().create_future()

        # Запускаем асинхронную задачу, которая запросит код у пользователя
        asyncio.create_task(self._get_2fa_code_from_user(prompts[0][0]))

        # Возвращаем future. AsyncSSH будет ждать, пока он не будет выполнен.
        return self._2fa_future

    async def _get_2fa_code_from_user(self, prompt_text: str):
        # Отправляем пользователю запрос от сервера
        msg = await self._bot.send_message(
            self._chat_id,
            f"🔐 Сервер запрашивает:\n`{prompt_text}`\n\nВведите требуемое значение:"
        )
        # Переводим FSM в состояние ожидания 2FA кода
        await self._state.set_state(SshSteps.wait_for_2fa)
        # Сохраняем future и id сообщения в FSM для следующего хендлера
        await self._state.update_data(
            two_fa_future=self._2fa_future,
            prompt_msg_id=msg.message_id
        )


@dp.message(StateFilter(SshSteps.wait_for_2fa))
async def process_2fa_code(message: Message, state: FSMContext):
    """Этот обработчик ловит только код 2FA от пользователя."""
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


@dp.message(StateFilter(SshSteps.get_server_info, SshSteps.get_server_info_for_existing))
async def handle_ssh_connection(message: Message, state: FSMContext):
    """
    Основная функция, которая ловит пароль и инициирует SSH подключение.
    Этот хендлер должен идти ПОСЛЕ хендлеров, которые ожидают `username@host`.
    """
    password = message.text
    chat_id = message.chat.id

    # Удаляем сообщения с паролем и запросом пароля
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
        # Фабрика будет создавать наш кастомный SSH клиент
        client_factory = lambda: CustomSshClient(bot, chat_id, state, password)

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

    except asyncssh.PermissionDenied as e:
        await bot.send_message(chat_id, f"❌ Ошибка аутентификации: Неверный пароль или код 2FA. {e}")
    except asyncssh.ProcessError as e:
        await bot.send_message(chat_id, f"❌ Ошибка выполнения команды на сервере:\n`{e.stderr}`", parse_mode="Markdown")
    except (asyncssh.Error, OSError) as e:
        await bot.send_message(chat_id, f"❌ Ошибка подключения: {e}")
    except Exception as e:
        logging.error(f"Неизвестная ошибка при SSH-подключении: {e}")
        await bot.send_message(chat_id, f"❌ Произошла неизвестная ошибка: {e}")
    finally:
        # Возвращаемся в главное меню
        await bot.send_message(
            chat_id,
            "Возвращаю в главное меню.",
            reply_markup=main_menu_keyboard
        )
        await state.set_state(SshSteps.main_menu)

# --- КОНЕЦ БЛОКА НА ЗАМЕНУ ---

async def main():
    """Основная функция для запуска бота"""
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())