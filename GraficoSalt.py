import pandas as pd
import matplotlib.pyplot as plt

# Substitua 'caminho/do/seu/arquivo.csv' pelo caminho real do seu arquivo
file_path = r'C:\Users\Utilizador\Desktop\Universidade\Mestrado\1ano\1semestre\Criptografia Aplicada\SecondProject\performance.csv'

# Lendo o arquivo usando o método read_csv do Pandas
data = pd.read_csv(file_path)

# Agrupando os dados pela coluna 'salt_size' e 'iterations' e calculando a média dos tempos
avg_time_by_salt_iterations = data.groupby(['salt_size', 'iterations'])['time_seconds'].mean().unstack()

# Criando o gráfico de barras para o tamanho do salt com base no número de iterações
plt.figure(figsize=(12, 6))
avg_time_by_salt_iterations.plot(kind='bar')
plt.xlabel('Tamanho do Salt')
plt.ylabel('Tempo Médio (segundos)')
plt.title('Tempo Médio por Tamanho do Salt e Número de Iterações')
plt.xticks(rotation=0)
plt.legend(title='Número de Iterações')
plt.grid(axis='y')
plt.tight_layout()

plt.show()
