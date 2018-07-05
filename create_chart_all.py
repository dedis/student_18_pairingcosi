#!/usr/bin/python3

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import sys

file_prefix = 'blsftcosi/simulation/test_data/bls_l_'
n_nodes = [5, 35, 140, 280, 560, 980]



fullRound_wall_avgs = []
fullRound_wall_devs = []

for n in n_nodes:
	filename = file_prefix + str(n) + '.csv'
	data = pd.read_csv(filename, nrows=1)
	fullRound_wall_avgs.append(data['fullRound_wall_avg'])
	fullRound_wall_devs.append(data['fullRound_wall_dev'])

plot_data = pd.DataFrame(n_nodes, columns=["n_nodes"])
plot_data['fullRound_wall_avg'] = fullRound_wall_avgs
plot_data['fullRound_wall_dev'] = fullRound_wall_devs

#####################################
file_prefix_pbft = 'pbft/simulation/test_data/pbft_l_'
n_nodes_pbft = [5, 35, 70, 100]

fullRound_wall_avgs_2 = []
fullRound_wall_devs_2 = []

for n in n_nodes_pbft:
	filename = file_prefix_pbft + str(n) + '.csv'
	data = pd.read_csv(filename, nrows=1)
	fullRound_wall_avgs_2.append(data['fullRound_wall_avg'])
	fullRound_wall_devs_2.append(data['fullRound_wall_dev'])

plot_data_2 = pd.DataFrame(n_nodes_pbft, columns=["n_nodes"])
plot_data_2['fullRound_wall_avg'] = fullRound_wall_avgs_2
plot_data_2['fullRound_wall_dev'] = fullRound_wall_devs_2

#####################################
file_prefix_bft = 'bftcosi_student/simulation/test_data/bft_l_'
n_nodes_bft = [5, 35, 140, 280]

fullRound_wall_avgs_3 = []
fullRound_wall_devs_3 = []

for n in n_nodes_bft:
	filename = file_prefix_bft + str(n) + '.csv'
	data = pd.read_csv(filename, nrows=1)
	fullRound_wall_avgs_3.append(data['round_wall_avg'])
	fullRound_wall_devs_3.append(data['round_wall_dev'])

plot_data_3 = pd.DataFrame(n_nodes_bft, columns=["n_nodes"])
plot_data_3['round_wall_avg'] = fullRound_wall_avgs_3
plot_data_3['round_wall_dev'] = fullRound_wall_devs_3



fig, ax = plt.subplots(figsize=(16,9))

ax.errorbar(n_nodes, plot_data['fullRound_wall_avg'], yerr=plot_data['fullRound_wall_dev'], label='BLS-ByzCoinX', fmt='bo-', elinewidth=2, capsize=5, capthick=2, color='coral', ecolor='black')
ax.errorbar(n_nodes_bft, plot_data_3['round_wall_avg'], yerr=plot_data_3['round_wall_dev'], label='ByzCoin', fmt='g-^', elinewidth=2, capsize=5, capthick=2, color='coral', ecolor='black')
ax.errorbar(n_nodes_pbft, plot_data_2['fullRound_wall_avg'], yerr=plot_data_2['fullRound_wall_dev'], label='PBFT', fmt='r-s', elinewidth=2, capsize=5, capthick=2, color='coral', ecolor='black')


ax.set_ylabel('Latency (seconds)', size='x-large')
ax.set_xlabel('Number of nodes', size='x-large')

handles, labels = ax.get_legend_handles_labels()
handles = [h[0] for h in handles]
ax.legend(handles, labels, loc='upper left', fontsize='xx-large')


plt.savefig("charts_l_all.png", format="png")
