import socket
import datetime

def receive_data(host='133.80.182.42', port=50000, max_retries=80):
    received_data_log = set()  # 受信済みデータのログ

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"Listening on {host}:{port}...")

        retries = 0
        while retries < max_retries:
            conn, addr = server_socket.accept()
            print(f"Connection established with {addr}")

            with conn:
                start_time = datetime.datetime.now()
                print(f"Start time: {start_time}")

                data = conn.recv(65535)
                if data:
                    decoded_data = data.decode('utf-8')
                    if decoded_data in received_data_log:
                        print("Duplicate data received. Skipping...")
                        conn.sendall(b"Duplicate data received. Skipping.")
                        continue

                    end_time = datetime.datetime.now()
                    elapsed_time = (end_time - start_time).total_seconds()

                    # ログに受信データを追加
                    received_data_log.add(decoded_data)

                    print(f"Received new data:\n{decoded_data}")
                    print(f"Time elapsed: {elapsed_time:.7f} seconds")

                    # データをファイルに保存
                    filename = f"received_data_{retries + 1}.txt"
                    with open(filename, 'w', encoding='utf-8') as file:
                        file.write(decoded_data)
                    print(f"Data saved to {filename}")

                    retries += 1
                    conn.sendall(b"Acknowledged")
                else:
                    print("No data received.")
        
        print("Maximum retries reached. Closing server.")

if __name__ == "__main__":
    receive_data()
