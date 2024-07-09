# DR-Store

The code for this work draws inspiration from the implementation of Waterbear.  Based on their work, we simulated the re-encoding process for BFT-Store and DR-Store.  Therefore, our code primarily focuses on simulating the re-encoding process using Docker containers and does not delve into the specific consensus implementation.

It is worth noting that our main modifications are concentrated in the broadcast process. For more details, please refer to the BroadCast folder. In practical implementation, please place the required folders (rbc or ecrbc) from the BroadCast directory into src/broadcast and modify the RBCTYPE in the configuration file etc/config to switch between using rbc and ecrbc. Please note that when testing with different numbers of nodes and different encoding schemes, both the config file and the code in the BroadCast folder need to be adjusted accordingly.

For specific integrated experimental results, please refer to Results.xlsx or Result.png.
