// Protocol Chart initialization
let protocolChart = null;

function updateProtocolChart() {
    fetch('/protocol-stats')
        .then(response => response.json())
        .then(data => {
            // Update total packets count
            document.getElementById('total-packets').textContent = data.total_packets;
            
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

function updateTopTalkers() {
    fetch('/top-talkers')
        .then(response => response.json())
        .then(data => {
            // Update senders table
            const sendersBody = document.getElementById('top-senders-body');
            sendersBody.innerHTML = data.top_senders.map((item, index) => `
                <tr>
                    <td>${index + 1}</td>
                    <td>${item.ip}</td>
                    <td>${item.formatted_bytes}</td>
                    <td>${item.packets}</td>
                </tr>
            `).join('');

            // Update receivers table
            const receiversBody = document.getElementById('top-receivers-body');
            receiversBody.innerHTML = data.top_receivers.map((item, index) => `
                <tr>
                    <td>${index + 1}</td>
                    <td>${item.ip}</td>
                    <td>${item.formatted_bytes}</td>
                    <td>${item.packets}</td>
                </tr>
            `).join('');
        });
}

// Start updating the chart when the page loads
document.addEventListener('DOMContentLoaded', function() {
    // Update chart every second
    setInterval(updateProtocolChart, 1000);
    
    // Update top talkers every second
    setInterval(updateTopTalkers, 1000);
});


