# main.py

from rsa_module import rsa_keygen, rsa_encrypt, rsa_decrypt
from kyber_module import kyber_keygen, kyber_encapsulate, kyber_decapsulate
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import time
import statistics
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import platform
import sys
import pkg_resources
import json
from datetime import datetime
import os

def get_system_info():
    """
    Collects system and environment information
    """
    system_info = {
        "os": platform.system() + " " + platform.release(),
        "python_version": sys.version,
        "processor": platform.processor(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "packages": {
            "pycryptodome": pkg_resources.get_distribution("pycryptodome").version,
            "kyber-py": pkg_resources.get_distribution("kyber-py").version,
            "plotly": pkg_resources.get_distribution("plotly").version
        },
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    return system_info

def measure_cpu_time():
    """
    Measures CPU time using time.process_time()
    """
    return time.process_time()

def aes_encrypt(message, key):
    """
    Encrypts the message using AES in EAX mode.
    Returns a tuple of (nonce, ciphertext, tag).
    """
    cipher_aes = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
    return cipher_aes.nonce, ciphertext, tag

def aes_decrypt(nonce, ciphertext, tag, key):
    """
    Decrypts the ciphertext using AES in EAX mode.
    Returns the decrypted plaintext.
    """
    cipher_aes = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return decrypted_message.decode()

def plot_file_results(filename, rsa_times, kyber_times, rsa_stdevs, kyber_stdevs, cpu_times):
    # Create figure with subplots for each variant
    fig = make_subplots(rows=5, cols=1,
                       subplot_titles=(f'RSA+AES Performance - {filename}',
                                     f'Kyber512 Performance - {filename}',
                                     f'Kyber768 Performance - {filename}',
                                     f'Kyber1024 Performance - {filename}',
                                     f'CPU Time Usage - {filename}'))

    # RSA+AES Plot with error bars
    fig.add_trace(
        go.Bar(name='RSA+AES',
               x=['Key Generation', 'Key Encryption', 'Message Encryption',
                  'Key Decryption', 'Message Decryption'],
               y=[rsa_times['keygen'], rsa_times['key_encrypt'],
                  rsa_times['msg_encrypt'], rsa_times['key_decrypt'],
                  rsa_times['msg_decrypt']],
               error_y=dict(
                   type='data',
                   array=[rsa_stdevs['keygen'], rsa_stdevs['key_encrypt'],
                         rsa_stdevs['msg_encrypt'], rsa_stdevs['key_decrypt'],
                         rsa_stdevs['msg_decrypt']],
                   visible=True
               )),
        row=1, col=1
    )

    # Kyber Plots for each variant
    for idx, level in enumerate([512, 768, 1024], start=2):
        fig.add_trace(
            go.Bar(name=f'Kyber{level}',
                   x=['Key Generation', 'Encapsulation', 'Decapsulation'],
                   y=[kyber_times[level]['keygen'], kyber_times[level]['encaps'],
                      kyber_times[level]['decaps']],
                   error_y=dict(
                       type='data',
                       array=[kyber_stdevs[level]['keygen'], kyber_stdevs[level]['encaps'],
                             kyber_stdevs[level]['decaps']],
                       visible=True
                   )),
            row=idx, col=1
        )

    # CPU Time Plot
    fig.add_trace(
        go.Bar(name='CPU Time',
               x=['RSA+AES'] + [f'Kyber{level}' for level in [512, 768, 1024]],
               y=[cpu_times['rsa_aes']] + [cpu_times[f'kyber{level}'] for level in [512, 768, 1024]]),
        row=5, col=1
    )

    # Update layout
    fig.update_layout(
        title_text=f'Cryptographic Operations Performance Comparison - {filename}',
        showlegend=True,
        height=2000
    )

    # Update y-axes labels
    for i in range(1, 5):
        fig.update_yaxes(title_text="Time (seconds)", row=i, col=1)
    fig.update_yaxes(title_text="CPU Time (seconds)", row=5, col=1)

    # Save the plot as HTML file
    output_filename = f"crypto_performance_{os.path.splitext(filename)[0]}.html"
    fig.write_html(output_filename)
    print(f"Performance visualization saved as '{output_filename}'")

def plot_comparison_results(all_results):
    # Create figure for size comparison
    fig = make_subplots(rows=2, cols=1,
                       subplot_titles=('Average Operation Time by Message Size',
                                     'CPU Time Usage by Message Size'))

    # Prepare data for plotting
    file_sizes = []
    rsa_total_times = []
    kyber_total_times = {512: [], 768: [], 1024: []}
    rsa_cpu_times = []
    kyber_cpu_times = {512: [], 768: [], 1024: []}
    
    for result in all_results:
        file_sizes.append(f"{result['test_parameters']['message_size']/1024:.2f} KB")
        
        # Calculate total times
        rsa_total = (result['results']['rsa_times']['keygen'] +
                    result['results']['rsa_times']['key_encrypt'] +
                    result['results']['rsa_times']['msg_encrypt'] +
                    result['results']['rsa_times']['key_decrypt'] +
                    result['results']['rsa_times']['msg_decrypt'])
        
        rsa_total_times.append(rsa_total)
        rsa_cpu_times.append(result['results']['cpu_times']['rsa_aes'])
        
        # Calculate Kyber totals for each variant
        for level in [512, 768, 1024]:
            kyber_total = (result['results']['kyber_times'][level]['keygen'] +
                          result['results']['kyber_times'][level]['encaps'] +
                          result['results']['kyber_times'][level]['decaps'])
            kyber_total_times[level].append(kyber_total)
            kyber_cpu_times[level].append(result['results']['cpu_times'][f'kyber{level}'])

    # Add traces for total operation times
    fig.add_trace(
        go.Scatter(name='RSA+AES Total Time',
                  x=file_sizes, y=rsa_total_times,
                  mode='lines+markers'),
        row=1, col=1
    )
    
    for level in [512, 768, 1024]:
        fig.add_trace(
            go.Scatter(name=f'Kyber{level} Total Time',
                      x=file_sizes, y=kyber_total_times[level],
                      mode='lines+markers'),
            row=1, col=1
        )

    # Add traces for CPU times
    fig.add_trace(
        go.Scatter(name='RSA+AES CPU Time',
                  x=file_sizes, y=rsa_cpu_times,
                  mode='lines+markers'),
        row=2, col=1
    )
    
    for level in [512, 768, 1024]:
        fig.add_trace(
            go.Scatter(name=f'Kyber{level} CPU Time',
                      x=file_sizes, y=kyber_cpu_times[level],
                      mode='lines+markers'),
            row=2, col=1
        )

    # Update layout
    fig.update_layout(
        title_text='Performance Comparison Across Message Sizes',
        showlegend=True,
        height=1000
    )

    # Update axes labels
    fig.update_xaxes(title_text="Message Size", row=1, col=1)
    fig.update_xaxes(title_text="Message Size", row=2, col=1)
    fig.update_yaxes(title_text="Total Time (seconds)", row=1, col=1)
    fig.update_yaxes(title_text="CPU Time (seconds)", row=2, col=1)

    # Save the plot
    fig.write_html("size_comparison.html")
    print("Size comparison visualization saved as 'size_comparison.html'")

def run_test_for_file(filename, num_iterations=100):
    """Run performance test for a single file"""
    print(f"\n=== Testing file: {filename} ===")
    
    # Lists to store timing data
    rsa_keygen_times = []
    rsa_encrypt_times = []
    aes_encrypt_times = []
    rsa_decrypt_times = []
    aes_decrypt_times = []
    
    # Kyber timing data for each variant
    kyber_times = {level: {'keygen': [], 'encaps': [], 'decaps': []} for level in [512, 768, 1024]}
    
    # CPU time measurements
    rsa_aes_cpu_time = 0
    kyber_cpu_times = {level: 0 for level in [512, 768, 1024]}
    
    # Read the message from the file
    with open(filename, "r") as file:
        message = file.read()
    
    message_size = len(message)
    print(f"Message Length: {message_size} characters ({message_size / 1024:.2f} KB)")
    
    for i in range(num_iterations):
        if i % 10 == 0:  # Progress indicator
            print(f"Completed {i}/{num_iterations} iterations...")
        
        # RSA+AES operations with CPU time measurement
        rsa_aes_cpu_start = measure_cpu_time()
        
        # RSA key generation timing
        start = time.perf_counter()
        rsa_pub, rsa_priv = rsa_keygen(2048)
        rsa_keygen_times.append(time.perf_counter() - start)
        
        # Generate a random AES key (256-bit)
        aes_key = get_random_bytes(32)
        
        # Encrypt the AES key using RSA
        start = time.perf_counter()
        encrypted_aes_key = rsa_encrypt(aes_key, rsa_pub)
        rsa_encrypt_times.append(time.perf_counter() - start)
        
        # Encrypt the message using AES
        start = time.perf_counter()
        nonce, aes_ciphertext, tag = aes_encrypt(message, aes_key)
        aes_encrypt_times.append(time.perf_counter() - start)
        
        # Decrypt the AES key using RSA
        start = time.perf_counter()
        decrypted_aes_key = rsa_decrypt(encrypted_aes_key, rsa_priv)
        rsa_decrypt_times.append(time.perf_counter() - start)
        
        # Decrypt the message using AES
        start = time.perf_counter()
        decrypted_message = aes_decrypt(nonce, aes_ciphertext, tag, decrypted_aes_key)
        aes_decrypt_times.append(time.perf_counter() - start)
        
        rsa_aes_cpu_time += measure_cpu_time() - rsa_aes_cpu_start
        
        # Verify RSA+AES correctness
        if message != decrypted_message:
            print("Error: RSA+AES Mismatch in decryption at iteration", i)
        
        # Test each Kyber variant
        for level in [512, 768, 1024]:
            kyber_cpu_start = measure_cpu_time()
            
            # Kyber timing
            start = time.perf_counter()
            kyber_pub, kyber_priv = kyber_keygen(level)
            kyber_times[level]['keygen'].append(time.perf_counter() - start)
            
            start = time.perf_counter()
            kyber_ct, kyber_ss = kyber_encapsulate(kyber_pub, level)
            kyber_times[level]['encaps'].append(time.perf_counter() - start)
            
            start = time.perf_counter()
            kyber_ss_dec = kyber_decapsulate(kyber_priv, kyber_ct, level)
            kyber_times[level]['decaps'].append(time.perf_counter() - start)
            
            kyber_cpu_times[level] += measure_cpu_time() - kyber_cpu_start
            
            # Verify Kyber correctness
            if kyber_ss != kyber_ss_dec:
                print(f"Error: Kyber{level} Mismatch in decryption at iteration", i)
    
    # Calculate statistics
    rsa_times = {
        'keygen': statistics.mean(rsa_keygen_times),
        'key_encrypt': statistics.mean(rsa_encrypt_times),
        'msg_encrypt': statistics.mean(aes_encrypt_times),
        'key_decrypt': statistics.mean(rsa_decrypt_times),
        'msg_decrypt': statistics.mean(aes_decrypt_times)
    }
    
    rsa_stdevs = {
        'keygen': statistics.stdev(rsa_keygen_times),
        'key_encrypt': statistics.stdev(rsa_encrypt_times),
        'msg_encrypt': statistics.stdev(aes_encrypt_times),
        'key_decrypt': statistics.stdev(rsa_decrypt_times),
        'msg_decrypt': statistics.stdev(aes_decrypt_times)
    }
    
    kyber_times_avg = {level: {
        'keygen': statistics.mean(kyber_times[level]['keygen']),
        'encaps': statistics.mean(kyber_times[level]['encaps']),
        'decaps': statistics.mean(kyber_times[level]['decaps'])
    } for level in [512, 768, 1024]}
    
    kyber_stdevs = {level: {
        'keygen': statistics.stdev(kyber_times[level]['keygen']),
        'encaps': statistics.stdev(kyber_times[level]['encaps']),
        'decaps': statistics.stdev(kyber_times[level]['decaps'])
    } for level in [512, 768, 1024]}
    
    cpu_times = {
        'rsa_aes': rsa_aes_cpu_time,
        'kyber512': kyber_cpu_times[512],
        'kyber768': kyber_cpu_times[768],
        'kyber1024': kyber_cpu_times[1024]
    }
    
    # Print results for this file
    print(f"\n=== Results for {filename} ===")
    print(f"Message size: {message_size} characters ({message_size / 1024:.2f} KB)")
    
    print("\n=== RSA+AES Hybrid Encryption Results ===")
    print("Average RSA Key Generation Time:        {:.4f}s ± {:.4f}s".format(
        rsa_times['keygen'], rsa_stdevs['keygen']))
    print("Average RSA AES Key Encryption Time:    {:.4f}s ± {:.4f}s".format(
        rsa_times['key_encrypt'], rsa_stdevs['key_encrypt']))
    print("Average AES Encryption Time:            {:.4f}s ± {:.4f}s".format(
        rsa_times['msg_encrypt'], rsa_stdevs['msg_encrypt']))
    print("Average RSA AES Key Decryption Time:    {:.4f}s ± {:.4f}s".format(
        rsa_times['key_decrypt'], rsa_stdevs['key_decrypt']))
    print("Average AES Decryption Time:            {:.4f}s ± {:.4f}s".format(
        rsa_times['msg_decrypt'], rsa_stdevs['msg_decrypt']))
    print(f"Total CPU Time:                        {rsa_aes_cpu_time:.4f}s")
    
    for level in [512, 768, 1024]:
        print(f"\n=== Kyber{level} Results ===")
        print("Average Key Generation Time:     {:.4f}s ± {:.4f}s".format(
            kyber_times_avg[level]['keygen'], kyber_stdevs[level]['keygen']))
        print("Average Encapsulation Time:      {:.4f}s ± {:.4f}s".format(
            kyber_times_avg[level]['encaps'], kyber_stdevs[level]['encaps']))
        print("Average Decapsulation Time:      {:.4f}s ± {:.4f}s".format(
            kyber_times_avg[level]['decaps'], kyber_stdevs[level]['decaps']))
        print(f"Total CPU Time:                 {kyber_cpu_times[level]:.4f}s")
    
    # Create individual plot for this file
    plot_file_results(filename, rsa_times, kyber_times_avg, rsa_stdevs, kyber_stdevs, cpu_times)
    
    return {
        "filename": filename,
        "test_parameters": {
            "message_size": message_size,
            "iterations": num_iterations,
            "rsa_key_size": 2048,
            "kyber_variants": [512, 768, 1024],
            "aes_key_size": 256
        },
        "results": {
            "rsa_times": rsa_times,
            "rsa_stdevs": rsa_stdevs,
            "kyber_times": kyber_times_avg,
            "kyber_stdevs": kyber_stdevs,
            "cpu_times": cpu_times
        }
    }

def run_all_tests(num_iterations=100):
    # Get system information
    system_info = get_system_info()
    
    # List of test files
    test_files = [
        "small_text_sample.txt",
        "medium_text_sample.txt",
        "large_text_sample.txt",
        "500_byte.txt",
        "large_message.txt",
        "6000_byte.txt",
        "10000_byte.txt"
    ]
    
    # Print test environment information
    print("\n=== Test Environment ===")
    print(f"OS: {system_info['os']}")
    print(f"Python: {system_info['python_version'].split()[0]}")
    print(f"Processor: {system_info['processor']}")
    print(f"Machine: {system_info['machine']}")
    print(f"CPU Cores: {system_info['cpu_count']}")
    print("\nPackage Versions:")
    for pkg, version in system_info['packages'].items():
        print(f"- {pkg}: {version}")
    
    print("\nRunning performance tests...")
    print(f"Number of iterations per file: {num_iterations}")
    print("RSA key size: 2048 bits")
    print("Kyber variants: Kyber512, Kyber768, Kyber1024")
    print("AES key size: 256 bits")
    
    # Run tests for each file
    all_results = []
    for filename in test_files:
        try:
            result = run_test_for_file(filename, num_iterations)
            all_results.append(result)
        except FileNotFoundError:
            print(f"\nWarning: File {filename} not found, skipping...")
            continue
    
    # Save all results to JSON
    results_data = {
        "system_info": system_info,
        "file_results": all_results
    }
    
    with open("all_benchmark_results.json", "w") as f:
        json.dump(results_data, f, indent=4)
    print("\nAll detailed results saved to 'all_benchmark_results.json'")
    
    # Create comparison visualization
    plot_comparison_results(all_results)

if __name__ == "__main__":
    run_all_tests(100)
