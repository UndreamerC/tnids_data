import pandas as pd
import os

def compare_csv_files(file1, file2, output_diff='diff_output.txt'):
    # 读取两个 CSV 文件
    csv1 = pd.read_csv(file1)
    csv2 = pd.read_csv(file2)

    with open(output_diff, 'w', encoding="utf-8") as out:
        # 检查形状是否相同
        if csv1.shape != csv2.shape:
            out.write(f"文件行列数量不同:\n{file1} 形状: {csv1.shape}\n{file2} 形状: {csv2.shape}\n\n")
        else:
            # 找出不同的位置，并输出其对应的位置（行，列）
            diff_locations = (csv1 != csv2) & ~(csv1.isnull() & csv2.isnull())
            differences = diff_locations.stack()

            if differences.any():
                for (row, col), _ in differences[differences].items():  # 使用 items() 代替 iteritems()
                    out.write(f"不一致位置: 行 {row + 1}, 列 '{col}' - {file1}: {csv1.loc[row, col]}, {file2}: {csv2.loc[row, col]}\n")
            else:
                out.write("两个CSV文件内容完全相同。\n")

    print(f"文件比较完成，结果已保存到 '{output_diff}' 中。")


def save_csv_samples(file_list):
    for file_name in file_list:
        try:
            # 读取前20行
            df = pd.read_csv(file_name, nrows=20)

            # 构造新文件名
            new_file_name = file_name.replace('.csv', '_sample.csv')

            # 保存前20行到新文件
            df.to_csv(new_file_name, index=False)
            print(f"Sample saved to {new_file_name}")

        except Exception as e:
            print(f"Error processing file {file_name}: {e}")
# 用法示例
print("Current Working Directory:", os.getcwd())
file1 = './Data/kitsune/ARP_MitM/output/ARP_MitM_feature.csv'
file2 = './Data/kitsune/ARP_MitM/ARP_MitM_labels.csv'
# save_csv_samples([file1,file2])
# file1=file1.replace('.csv', '_sample.csv')
# file2=file2.replace('.csv', '_sample.csv')
compare_csv_files(file1, file2,'./Data/kitsune/ARP_MitM/diff_output.txt')
