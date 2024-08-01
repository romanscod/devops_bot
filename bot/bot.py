import logging
import re
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ConversationHandler, ContextTypes, CallbackQueryHandler

import paramiko
import json

from dotenv import load_dotenv
import os

import psycopg2

load_dotenv()

TOKEN = os.getenv('TOKEN')
rm_host = os.getenv('RM_HOST')
rm_port = os.getenv('RM_PORT')
rm_user = os.getenv('RM_USER')
rm_password = os.getenv('RM_PASSWORD')
db_user = os.getenv('DB_USER')
db_password = os.getenv('DB_PASSWORD')
db_host = os.getenv('DB_HOST')
db_port = os.getenv('DB_PORT')
db_database = os.getenv('DB_DATABASE')
db_repl_user = os.getenv('DB_REPL_USER')
db_repl_password = os.getenv('DB_REPL_PASSWORD')
db_repl_host = os.getenv('DB_REPL_HOST')
db_repl_port = os.getenv('DB_REPL_PORT')
#local_ip = "192.168.212.151"

# Подключаем логирование
logging.basicConfig(
    filename='./logfile.txt',
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    )
logger = logging.getLogger(__name__)

async def find_phone_numbers_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text('Введите текст для поиска телефонных номеров: ')
    return 'find_phone_numbers'

async def find_phone_numbers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_input = update.message.text  # Получаем текст, с номерами
    regex_filters = [
        re.compile(r'\b8\d{10}\b'),                          # 8XXXXXXXXXX
        re.compile(r'\+7\d{10}\b'),                          # +7XXXXXXXXXX
        re.compile(r'\b8\(\d{3}\)\d{7}\b'),                  # 8(XXX)XXXXXXX
        re.compile(r'\+7\(\d{3}\)\d{7}\b'),                  # +7(XXX)XXXXXXX
        re.compile(r'\b8 \d{3} \d{3} \d{2} \d{2}\b'),        # 8 XXX XXX XX XX
        re.compile(r'\+7 \d{3} \d{3} \d{2} \d{2}\b'),        # +7 XXX XXX XX XX
        re.compile(r'\b8 \(\d{3}\) \d{3} \d{2} \d{2}\b'),    # 8 (XXX) XXX XX XX
        re.compile(r'\+7 \(\d{3}\) \d{3} \d{2} \d{2}\b'),    # +7 (XXX) XXX XX XX
        re.compile(r'\b8-\d{3}-\d{3}-\d{2}-\d{2}\b'),        # 8-XXX-XXX-XX-XX
        re.compile(r'\+7-\d{3}-\d{3}-\d{2}-\d{2}\b'),        # +7-XXX-XXX-XX-XX
        ]
    phone_number_list = []
    for filter in regex_filters:
        phone_number_list.extend(filter.findall(user_input))  # Ищем номера телефонов по каждому шаблону

    if not phone_number_list:  # Если нет номеров
        await update.message.reply_text('Телефонные номера не найдены')
        return ConversationHandler.END  # Завершаем работу обработчика диалога
    keyboard = [[InlineKeyboardButton("Записать в базу данных ✅", callback_data=f"Save_phones"),
                     InlineKeyboardButton("Пропустить ❌", callback_data=f"Pass")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    phone_numbers = '\n'.join([f'{i+1}. {num}' for i, num in enumerate(phone_number_list)])  # Создаем строку с номерами телефонов
    await update.message.reply_text(phone_numbers,reply_markup=reply_markup)  # Отправляем сообщение пользователю
    context.user_data['phone_numbers'] = phone_number_list
    return ConversationHandler.END  # Завершаем работу обработчика диалога

async def response_button(update, context):
    if not context:
        return
    query = update.callback_query
    msg_id = query.message.message_id
    data = str(query.data)
    current_msg = query.message.text

    await query.answer()

    if data == "Save_phones":
        new_msg = f"{current_msg}\nСохранить данные ✅!" #добавленный текст в исходное сообщение
        unswer = save_to_db(tables_name = "phones",column = "phone_number",text = context.user_data.get('phone_numbers', [])) 
        if unswer:
            await context.bot.send_message(chat_id=query.message.chat.id, text="Данные сохранены в базе данных") #вывод в чат
        else:
            await context.bot.send_message(chat_id=query.message.chat.id, text="Ошибка сохранения данных")
    elif data == "Save_emails":
        new_msg = f"{current_msg}\nСохранить данные ✅!"
        unswer = save_to_db(tables_name ="emails",column = "email_address" ,text = context.user_data.get('emails', []))
        if unswer:
            await context.bot.send_message(chat_id=query.message.chat.id, text="Данные сохранены в базе данных")
        else:
            await context.bot.send_message(chat_id=query.message.chat.id, text="Ошибка сохранения данных")
    elif data == "Pass":
        new_msg = f"{current_msg}\nНе сохранять данные ⛔!"
    await context.bot.edit_message_text( #обновление сообщения после нажатия на кнопку
        text=new_msg,
        chat_id=query.message.chat_id,
        message_id=msg_id,
        reply_markup=None  # Удаление кнопок
    )

def save_to_db(tables_name,column,text):
    try:
        with psycopg2.connect(dbname=db_database, user=db_user, password=db_password, host=db_host, port=db_port) as conn:
            cursor = conn.cursor()
            query = f"INSERT INTO {tables_name} ({column}) VALUES (%s)"
            for line in text:
                cursor.execute(query, (line,))
            conn.commit()
        return True #возврат True если запись прошла успешно
    except:
        init_sqlite()
        return False


def read_from_db(tables_name):
    try:
        with psycopg2.connect(dbname=db_database, user=db_user, password=db_password, host=db_host, port=db_port) as conn:
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {tables_name}")
            all_rows = cursor.fetchall()
            conn.commit()
        return all_rows
    except:
        init_sqlite()
        return False

async def find_email_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text('Введите текст для поиска email адресов: ')
    return 'find_email'


async def find_email(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_input = update.message.text  # Получаем текст с email адресами
    email_regex = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')  # Шаблон для поиска email адресов
    email_list = email_regex.findall(user_input)  # Ищем email адреса
    if not email_list:  # Обрабатываем случай, когда email адреса нет
        await update.message.reply_text('Email адреса не найдены')
        return ConversationHandler.END  # Завершаем работу обработчика 
    
    keyboard = [[InlineKeyboardButton("Записать в базу данных ✅", callback_data=f"Save_emails"),
                     InlineKeyboardButton("Пропустить ❌", callback_data=f"Pass")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    emails = '\n'.join([f'{i+1}. {email}' for i, email in enumerate(email_list)])  # Создаем строку с email адресами
    await update.message.reply_text(emails,reply_markup=reply_markup)  # Отправляем сообщение пользователю
    context.user_data['emails'] = email_list
    return ConversationHandler.END  # Завершаем работу обработчика диалога


async def verify_password_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text('Введите пароль для проверки: ')
    return 'verify_password'


async def verify_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    password = update.message.text.strip()  # Получаем введенный пользователем пароль
    password_regex = re.compile(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()])[A-Za-z\d!@#$%^&*()]{8,}$')
    is_complex = bool(password_regex.match(password))
    if is_complex:
        await update.message.reply_text('Пароль сложный')
    else:
        await update.message.reply_text('Пароль простой')
    return ConversationHandler.END

async def get_info(update: Update, context: ContextTypes.DEFAULT_TYPE, command):
    try:
        # Устанавливаем соединение по SSH
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=rm_host, port=rm_port, username=rm_user, password=rm_password)

        # Выполняем команду на удаленном сервере
        stdin, stdout, stderr = client.exec_command(command)
        data = stdout.read() + stderr.read()
        client.close()

        # Обработка полученных данных
        data = str(data, 'utf-8').replace('\\n', '\n').replace('\\t', '\t').strip()

        if data == "":
            await update.message.reply_text(f"Нет запрашиваемых данных")
        elif data == "WARNING: apt does not have a stable CLI interface. Use with caution in scripts.":
            await update.message.reply_text(f"Запрашиваемый пакет не установлен")
        else:
            size = 4096
            for i in range(0, len(data), size):                 #обработка большого текста
                await update.message.reply_text(data[i:i+size])
        # Отправляем полученные данные пользователю в Telegram
        
    except Exception as e:
        await update.message.reply_text(f"Произошла ошибка при выполнении SSH: {str(e)}")
    return ConversationHandler.END

#вызов функции get_info с передачей определенной команды
async def get_release(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await get_info(update, context, 'lsb_release -a')

async def get_uname(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await get_info(update, context, 'uname -a')

async def get_uptime(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await get_info(update, context, 'uptime')

async def get_df(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await get_info(update, context, 'df -h')

async def get_free(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await get_info(update, context, 'free')

async def get_mpstat(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await get_info(update, context, 'who') 
    
async def get_w(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await get_info(update, context, 'w')

async def get_auths(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await get_info(update, context, 'last -n 10') 

async def get_critical(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await get_info(update, context, 'sudo grep "CRITICAL" /var/log/syslog | tail -n 5') 

async def get_ps(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await get_info(update, context, 'ps')

async def get_ss(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await get_info(update, context, 'ss')

async def show_apt_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_input = update.message.text.strip()
    if user_input.lower() == 'all':
        command = 'apt list --installed'
    else:
        command = f'apt list --installed | grep {user_input}'
    await get_info(update, context, command)
    return ConversationHandler.END

async def start_get_apt_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Введите имя пакета, чтобы его увидеть, либо 'All', чтобы увидеть весь список")
    return 'get_apt_list'

async def get_services(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await get_info(update, context, 'systemctl list-units --type=service --state=running')

async def get_repl_logs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text('Логи мастер сервера: ')
    await get_info(update, context, f'sudo docker logs --tail 10 {db_host}')
    await update.message.reply_text('Логи подчиненного сервера: ')
    await get_info(update, context, f'sudo docker logs --tail 10 {db_repl_host}')


async def get_emails(update: Update, context: ContextTypes.DEFAULT_TYPE):
    all_emails = read_from_db('emails')
    if not all_emails:
        await update.message.reply_text("База данных пустая.")
        return
    reply_message = "Email-адреса в базе данных:\n"
    for line in all_emails:
        reply_message += f"{line[0]}: \"{line[1]}\"\n"
    await update.message.reply_text(reply_message)

async def get_phone_numbers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    all_numbers = read_from_db('phones')
    if not all_numbers:
        await update.message.reply_text("База данных пустая.")
        return
    reply_message = "Телефонные номера в базе данных:\n"
    for line in all_numbers:
        reply_message += f"{line[0]}: \"{line[1]}\"\n"
    await update.message.reply_text(reply_message)

async def list_all_commands(update: Update, context: ContextTypes.DEFAULT_TYPE):
    all_commands = """
        Доступные команды:
        / или /help - список всех команд
        /find_email - получить email адреса из текста
        /find_phone_numbers - получить все телефонные номера из текста
        /verify_password - проверка сложности пароля
        /get_release - сбор информации о релизе системы
        /get_uname - сбор информации об архитектуры процессора
        /get_uptime - сбор информации о времени работы
        /get_df - Сбор информации о состоянии файловой системы.
        /get_free - Сбор информации о состоянии оперативной памяти. 
        /get_mpstat - Сбор информации о производительности системы.
        /get_w - Сбор информации о работающих в данной системе пользователях. 
        /get_auths - Сбор логов. Последние 10 входов в систему. 
        /get_critical - Сбор логов. Последние 5 критических события. 
        /get_ps - Сбор информации о запущенных процессах. 
        /get_ss - Сбор информации об используемых портах. 
        /get_apt_list - Сбор информации об установленных пакетах. 
        /get_services - Сбор информации о запущенных сервисах. 
        /get_repl_logs - Сбор информации о логах репликации postgresql
        /get_phone_numbers - Вывод сохраненных номеров из базы данных
        /get_emails - Вывод сохраненных email-адресов из базы данных
        """
    await update.message.reply_text(all_commands)

def init_sqlite():
    #создание основной БД с заявками
    try:
        with psycopg2.connect(dbname=db_database, user=db_user, password=db_password, host=db_host, port=db_port) as conn:
            cur = conn.cursor()
            cur.execute('''CREATE TABLE IF NOT EXISTS phones (
                    id SERIAL PRIMARY KEY,
                    phone_number TEXT NOT NULL
                   )''') 
            conn.commit()
    except psycopg2.Error as e:
        print('Ошибка подключения к таблице requests',e)
    try:
        with psycopg2.connect(dbname=db_database, user=db_user, password=db_password, host=db_host, port=db_port) as conn:
            cur = conn.cursor()
            cur.execute('''CREATE TABLE IF NOT EXISTS emails (
                    id SERIAL PRIMARY KEY,
                    email_address TEXT NOT NULL
                   )''') 
            conn.commit()
    except psycopg2.Error as e:
        print('Ошибка подключения к таблице requests',e)

def main():
    init_sqlite() #проверка доступа к БД и создание таблицы при отсутствии. 
    application = Application.builder().token(TOKEN).build()
    # Обработчик для телефонных номеров
    conv_handler_find_phone_numbers = ConversationHandler(
        entry_points=[CommandHandler('find_phone_numbers', find_phone_numbers_command)],
        states={'find_phone_numbers': [MessageHandler(filters.TEXT & ~filters.COMMAND, find_phone_numbers)],},
        fallbacks=[],
        )
    
    # Обработчик для email адресов
    conv_handler_find_email = ConversationHandler(
        entry_points=[CommandHandler('find_email', find_email_command)],
        states={'find_email': [MessageHandler(filters.TEXT & ~filters.COMMAND, find_email)],},
        fallbacks=[],
    )

    # Обработчик для паролей
    conv_handler_verify_password = ConversationHandler(
        entry_points=[CommandHandler('verify_password', verify_password_command)],
        states={
            'verify_password': [MessageHandler(filters.TEXT & ~filters.COMMAND, verify_password)],
        },
        fallbacks=[],
    )
    # Обработчик для apt пакетов
    conv_handler_apt_list = ConversationHandler(
        entry_points=[CommandHandler('get_apt_list', start_get_apt_list)],
        states={
            'get_apt_list': [MessageHandler(filters.TEXT & ~filters.COMMAND, show_apt_list)],
        },
        fallbacks=[],
    )
    # Обработчик для сервисов

    application.add_handler(conv_handler_find_phone_numbers)
    application.add_handler(conv_handler_find_email)
    application.add_handler(conv_handler_verify_password)
    commands = [
    ("get_release", get_release),
    ("get_uname", get_uname),
    ("get_uptime", get_uptime),
    ("get_df", get_df),
    ("get_free", get_free),
    ("get_mpstat", get_mpstat),
    ("get_w", get_w),
    ("get_auths", get_auths),
    ("get_critical", get_critical),
    ("get_ps", get_ps),
    ("get_ss", get_ss),
    ("get_services", get_services),
    ("get_repl_logs", get_repl_logs),
    ("get_emails", get_emails),
    ("get_phone_numbers", get_phone_numbers),
    ]
    for command, handler in commands:
        application.add_handler(CommandHandler(command, handler)) #проверка комманды из списка
    application.add_handler(MessageHandler(filters.Regex(r'^/($|help$)'), list_all_commands))
    application.add_handler(CallbackQueryHandler(response_button))
    application.add_handler(conv_handler_apt_list)
    # Запуск бота
    application.run_polling()

if __name__ == '__main__':
    main()
