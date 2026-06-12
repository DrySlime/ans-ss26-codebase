## 1. System Components

* **`topology_iperf_mininet_test.py`**: Instantiates the Mininet network namespace, constructs the Fat-Tree topology ($k=4$), and orchestrates the `iperf` traffic generation.
* **`visualize_topo_test.py`**: Renders a graph visualization of the network topology. 
    * Execution: `python3 visualize_topo_test.py`
* **`run_test.sh`**: Environment wrapper for Mininet initialization. Injects `PYTHONPATH` and invokes the topology script via `sudo`.
* **`./test_results/plot_test.py`**: Data parser and visualization script. Consumes aggregated JSON metrics to plot comparative traffic analysis.
* **`structure_test.py`**: Mathematically test the topology and verify expected connections and number of nodes etc

## 2. Execution Pipeline

### Phase A: Topology Initialization
In the primary terminal, trigger the Mininet environment:
```bash
./run_test.sh
```
### Phase B: Controller Deployment
Establish a secondary SSH connection to the VM while Mininet initializes. Deploy the Ryu controller specifying the target routing application.

Option 1: Fault-Tolerant Routing
```bash
ryu-manager ./ft_routing.py --observe-links
```
Option 2: Shortest Path Routing
```bash
ryu-manager ./sp_routing.py --observe-links
```
### Phase C: Data Aggregation & Archiving

Upon test completion, the framework writes raw throughput metrics to traffic_results.json. Rename this artifact immediately to prevent state overwriting in subsequent iterations.
```bash
# Following the FT routing test:
mv traffic_results.json test_results/ft_results.json

# Following the SP routing test:
mv traffic_results.json test_results/sp_results.json
```
### Phase D: Visualization
Once both ft_results.json and sp_results.json reside in the working directory, invoke the plotting script. The resulting image artifact is dumped to the current working directory.
```bash
python3 ./test_results/plot_test.py
```