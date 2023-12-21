import pandas as pd
import matplotlib.pyplot as plt

# Substitua 'caminho/do/seu/arquivo.csv' pelo caminho real do seu arquivo
file_path = r'C:\Users\Utilizador\Desktop\Universidade\Mestrado\1ano\1semestre\Criptografia Aplicada\SecondProject\performance.csv'

# Lendo o arquivo usando o método read_csv do Pandas
data = pd.read_csv(file_path)

# Agrupando os dados pela coluna 'password_size' e calculando a média dos tempos
avg_time_by_password = data.groupby('password_size')['time_seconds'].mean()

# Ordenando os valores pela senha para manter a ordem na plotagem do gráfico de barras
avg_time_by_password = avg_time_by_password.sort_index()

# Criando o gráfico de barras
plt.figure(figsize=(10, 6))
avg_time_by_password.plot(kind='bar', color='skyblue')
plt.xlabel('Tamanho da Password(caracteres)')
plt.ylabel('Tempo Médio (segundos)')
plt.title('Tempo Médio por Tamanho da Password')
plt.xticks(rotation=0)  # Rotaciona os rótulos do eixo x para melhor legibilidade
plt.grid(axis='y')  # Adiciona grade apenas no eixo y
plt.tight_layout()

plt.show()
