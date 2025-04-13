import ipaddress
import asyncio
import csv
import time
from collections import defaultdict
from tqdm import tqdm

# Список активных подсетей
ACTIVE_SUBNETS = [
    "8.8.8.0/24",  # Google DNS
    "1.1.1.0/24",  # Cloudflare DNS
    "172.217.0.0/16",  # Google
    "104.16.0.0/12",  # Cloudflare
    "192.30.252.0/22",  # GitHub
    "13.32.0.0/15",  # Amazon AWS
    "157.240.0.0/16",  # Facebook
    "151.101.0.0/16",  # Fastly CDN
    "198.41.128.0/17",  # Cloudflare
    "35.190.0.0/17",  # Google Cloud
    "52.0.0.0/11",  # Amazon AWS
    "34.0.0.0/8",      # Google Cloud Platform
    "199.232.0.0/16",  # GitHub Pages
    "140.82.112.0/20", # GitHub
    "185.199.108.0/22", # GitHub Pages
    "20.0.0.0/8",      # Microsoft Azure
    "40.64.0.0/10",    # Microsoft Azure
    "104.244.40.0/21", # Twitter
    "69.171.250.0/24", # Facebook
    "31.13.64.0/18",   # Facebook
    "66.220.144.0/20", # Facebook
    "208.80.152.0/22", # Wikimedia
    "91.198.174.0/24", # Wikimedia
    "103.102.166.0/24", # Cloudflare
    "173.245.48.0/20", # Cloudflare
    "190.93.240.0/20", # Cloudflare
    "205.251.192.0/18", # Amazon CloudFront
    "54.230.0.0/16",   # Amazon CloudFront
    "99.84.0.0/16",    # Amazon CloudFront
    "204.79.197.0/24", # Microsoft
    "23.0.0.0/8",      # Akamai
    "96.16.0.0/15",    # Akamai
    "72.21.0.0/16",    # Amazon
    "74.125.0.0/16",   # Google
    "216.58.192.0/19", # Google
]

# Порты для проверки доступности
PORTS_TO_CHECK = [80, 443, 22, 21, 8080, 8443, 53, 25, 23, 8000, 2375]

# Максимальное количество одновременных проверок
MAX_CONCURRENT_CHECKS = 1000

# Таймаут для проверки порта (в секундах)
PORT_CHECK_TIMEOUT = 0.5


def generate_ips_from_subnets(subnets, max_ips_per_subnet=10000):
    """Генерирует IP-адреса из списка активных подсетей"""
    ip_addresses = []

    for subnet_str in subnets:
        subnet = ipaddress.IPv4Network(subnet_str)
        # Ограничиваем количество IP из каждой подсети
        count = min(max_ips_per_subnet, subnet.num_addresses)

        # Берем равномерно распределенные адреса из подсети
        step = max(1, subnet.num_addresses // (count * 16))
        for i in range(0, min(subnet.num_addresses, count * step), step):
            ip = subnet.network_address + i
            ip_addresses.append(str(ip))

    return ip_addresses


def calculate_ip_sum(ip_str):
    """Вычисляет сумму всех чисел (октетов) в IP-адресе"""
    octets = [int(octet) for octet in ip_str.split('.')]
    return sum(octets)


async def check_port_async(ip, port):
    """Асинхронная проверка открытости порта"""
    try:
        # Создаем футуру для подключения к порту
        conn = asyncio.open_connection(ip, port)
        # Ждем подключения с таймаутом
        reader, writer = await asyncio.wait_for(conn, timeout=PORT_CHECK_TIMEOUT)
        # Если подключились, закрываем соединение
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


async def check_ip_async(ip):
    """Асинхронная проверка IP-адреса по нескольким портам"""
    for port in PORTS_TO_CHECK:
        if await check_port_async(ip, port):
            return ip, f"port_{port}_open"
    return None


async def check_ip_batch(ip_batch, semaphore):
    """Проверка пакета IP-адресов с использованием семафора для ограничения"""
    tasks = []
    for ip in ip_batch:
        # Используем семафор для ограничения количества одновременных проверок
        async with semaphore:
            tasks.append(asyncio.create_task(check_ip_async(ip)))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if r is not None and not isinstance(r, Exception)]


async def main():
    # Генерируем IP-адреса из активных подсетей
    print("Генерация IP-адресов из активных подсетей...")
    ip_addresses = generate_ips_from_subnets(ACTIVE_SUBNETS, max_ips_per_subnet=200)
    print(f"Сгенерировано {len(ip_addresses)} IP-адресов")

    # Создаем семафор для ограничения количества одновременных проверок
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)

    # Проверяем доступность IP-адресов
    print("Проверка доступности IP-адресов...")
    start_time = time.time()

    # Разбиваем IP-адреса на пакеты для более эффективной обработки
    batch_size = 1000
    ip_batches = [ip_addresses[i:i + batch_size] for i in range(0, len(ip_addresses), batch_size)]

    accessible_ips = []
    for i, batch in enumerate(ip_batches):
        print(f"Обработка пакета {i + 1}/{len(ip_batches)}...")
        batch_results = await check_ip_batch(batch, semaphore)
        accessible_ips.extend(batch_results)
        print(f"Найдено {len(batch_results)} доступных IP-адресов в пакете")

    elapsed = time.time() - start_time
    print(f"Проверка завершена за {elapsed:.2f} секунд")
    print(f"Найдено {len(accessible_ips)} доступных IP-адресов")

    # Группируем IP-адреса по сумме их чисел
    print("Поиск пар IP-адресов с равной суммой чисел...")
    sum_groups = defaultdict(list)

    for ip_info in accessible_ips:
        if ip_info:
            ip, accessibility = ip_info
            ip_sum = calculate_ip_sum(ip)
            sum_groups[ip_sum].append((ip, accessibility))

    # Находим пары с одинаковой суммой
    pairs = []
    for ip_sum, ip_list in sum_groups.items():
        if len(ip_list) >= 2:
            # Создаем пары из IP-адресов с одинаковой суммой
            for i in range(len(ip_list)):
                for j in range(i + 1, len(ip_list)):
                    ip1, access1 = ip_list[i]
                    ip2, access2 = ip_list[j]
                    pairs.append((ip1, access1, ip2, access2, f"equal_sum={ip_sum}"))

    print(f"Найдено {len(pairs)} пар IP-адресов с равной суммой чисел")

    # Сохраняем результаты в CSV-файл
    with open('ip_pairs_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(
            ['IPv4-адрес 1', 'Критерий доступности 1', 'IPv4-адрес 2', 'Критерий доступности 2', 'Признак совпадения'])
        writer.writerows(pairs)

    print(f"Результаты сохранены в файл ip_pairs_results.csv")

    # Также сохраняем все доступные IP-адреса для справки
    with open('accessible_ips.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['IPv4-адрес', 'Критерий доступности', 'Сумма чисел'])
        for ip_info in accessible_ips:
            if ip_info:
                ip, accessibility = ip_info
                writer.writerow([ip, accessibility, calculate_ip_sum(ip)])

    print(f"Список всех доступных IP-адресов сохранен в файл accessible_ips.csv")


if __name__ == "__main__":
    # Запускаем асинхронную функцию
    asyncio.run(main())
