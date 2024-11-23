// Protocol Chart initialization
let protocolChart = null;

function updateProtocolChart() {
    fetch('/protocol-stats')
        .then(response => response.json())
        .then(data => {
            const ctx = document.getElementById('protocolChart').getContext('2d');
            
            // Define protocol order (Other will be automatically last)
            const protocolOrder = ['ARP', 'ICMP', 'TCP', 'UDP'];
            
            // Sort the data according to protocol order
            const sortedLabels = Object.keys(data.counts).sort((a, b) => {
                if (a === 'Other') return 1;  // Other always goes last
                if (b === 'Other') return -1;
                return protocolOrder.indexOf(a) - protocolOrder.indexOf(b);
            });
            
            // Get corresponding values in the same order
            const sortedPercentages = sortedLabels.map(label => data.percentages[label]);
            
            // Destroy existing chart if it exists
            if (protocolChart) {
                protocolChart.destroy();
            }
            
            // Create new chart
            protocolChart = new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: sortedLabels,
                    datasets: [{
                        data: sortedPercentages,
                        backgroundColor: [
                            '#FF6384',   // ARP
                            '#36A2EB',   // ICMP
                            '#FFCE56',   // TCP
                            '#4BC0C0',   // UDP
                            '#9966FF'    // Other
                        ]
                    }]
                },
                options: {
                    animation: {
                        duration: 0
                    },
                    responsive: true,
                    plugins: {
                        title: {
                            display: true,
                            text: 'Protocol Distribution'
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const label = context.label || '';
                                    const value = context.raw.toFixed(1);
                                    const count = data.counts[label];
                                    return `${label}: ${value}% (${count} packets)`;
                                }
                            }
                        }
                    }
                }
            });
        });
}

// Start updating the chart when the page loads
document.addEventListener('DOMContentLoaded', function() {
    // Update chart every second when sniffing is active
    setInterval(updateProtocolChart, 1000);
});
