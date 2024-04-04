import streamlit as st
import pandas as pd
import numpy as np
from keras.models import load_model
from sklearn.preprocessing import StandardScaler, LabelEncoder
import pickle

# Load model, scaler, and label encoder
model = load_model('best_model_cnn.keras')
scaler = pickle.load(open('scaler.pkl', 'rb'))
label_encoder = pickle.load(open('label_encoder.pkl', 'rb'))

def preprocess_data(input_data):
    # Scaling
    scaled_data = scaler.transform(input_data)
    # Reshaping for the CNN
    reshaped_data = scaled_data.reshape(scaled_data.shape[0], scaled_data.shape[1], 1)
    return reshaped_data

def predict(data):
    preprocessed_data = preprocess_data(data)
    predictions_categorical = model.predict(preprocessed_data)
    predictions = np.argmax(predictions_categorical, axis=1)
    return label_encoder.inverse_transform(predictions)

def show_form_page():
    st.title("Intrusion Detection System")
    
    # User inputs for all selected features
    destination_port = st.number_input("Destination Port", min_value=0)
    flow_duration = st.number_input("Flow Duration", min_value=0)
    total_length_fwd_packets = st.number_input("Total Length of Fwd Packets", min_value=0)
    total_length_bwd_packets = st.number_input("Total Length of Bwd Packets", min_value=0)
    fwd_packet_length_max = st.number_input("Fwd Packet Length Max", min_value=0.0)
    fwd_packet_length_mean = st.number_input("Fwd Packet Length Mean", min_value=0.0)
    bwd_packet_length_max = st.number_input("Bwd Packet Length Max", min_value=0.0)
    bwd_packet_length_mean = st.number_input("Bwd Packet Length Mean", min_value=0.0)
    flow_bytes_per_s = st.number_input("Flow Bytes/s", min_value=0.0)
    fwd_header_length = st.number_input("Fwd Header Length", min_value=0)
    bwd_header_length = st.number_input("Bwd Header Length", min_value=0)
    max_packet_length = st.number_input("Max Packet Length", min_value=0.0)
    packet_length_mean = st.number_input("Packet Length Mean", min_value=0.0)
    packet_length_std = st.number_input("Packet Length Std", min_value=0.0)
    packet_length_variance = st.number_input("Packet Length Variance", min_value=0.0)
    average_packet_size = st.number_input("Average Packet Size", min_value=0.0)
    avg_bwd_segment_size = st.number_input("Avg Bwd Segment Size", min_value=0.0)
    subflow_bwd_bytes = st.number_input("Subflow Bwd Bytes", min_value=0)
    init_win_bytes_forward = st.number_input("Init_Win_bytes_forward", min_value=0)
    min_seg_size_forward = st.number_input("min_seg_size_forward", min_value=0)

    # Organize user inputs into a DataFrame
    input_dict = {
        'Destination Port': destination_port,
        'Flow Duration': flow_duration,
        'Total Length of Fwd Packets': total_length_fwd_packets,
        'Total Length of Bwd Packets': total_length_bwd_packets,
        'Fwd Packet Length Max': fwd_packet_length_max,
        'Fwd Packet Length Mean': fwd_packet_length_mean,
        'Bwd Packet Length Max': bwd_packet_length_max,
        'Bwd Packet Length Mean': bwd_packet_length_mean,
        'Flow Bytes/s': flow_bytes_per_s,
        'Fwd Header Length': fwd_header_length,
        'Bwd Header Length': bwd_header_length,
        'Max Packet Length': max_packet_length,
        'Packet Length Mean': packet_length_mean,
        'Packet Length Std': packet_length_std,
        'Packet Length Variance': packet_length_variance,
        'Average Packet Size': average_packet_size,
        'Avg Bwd Segment Size': avg_bwd_segment_size,
        'Subflow Bwd Bytes': subflow_bwd_bytes,
        'Init_Win_bytes_forward': init_win_bytes_forward,
        'min_seg_size_forward': min_seg_size_forward
    }
    input_df = pd.DataFrame([input_dict])

    # Predict button
    if st.button("Predict"):
        prediction = predict(input_df)
        st.success(f"The predicted label is: {prediction[0]}")
        
def show_file_upload_page():
    st.title("Intrusion Detection System")

    # File uploader
    uploaded_file = st.file_uploader("Choose a file (CSV or PCAP)", type=['csv', 'pcap'])
    
    if uploaded_file is not None:
        # Process CSV files
        if uploaded_file.type == "text/csv":
            # Read the CSV file into a DataFrame
            input_df = pd.read_csv(uploaded_file)

            # Complete column renaming mapping
            mapping = {
                ' Destination Port': 'Destination Port',
                ' Flow Duration': 'Flow Duration',
                ' Total Length of Fwd Packets': 'Total Length of Fwd Packets',
                ' Total Length of Bwd Packets': 'Total Length of Bwd Packets',
                ' Fwd Packet Length Max': 'Fwd Packet Length Max',
                ' Fwd Packet Length Mean': 'Fwd Packet Length Mean',
                ' Bwd Packet Length Max': 'Bwd Packet Length Max',
                ' Bwd Packet Length Mean': 'Bwd Packet Length Mean',
                ' Flow Bytes/s': 'Flow Bytes/s',
                ' Fwd Header Length': 'Fwd Header Length',
                ' Bwd Header Length': 'Bwd Header Length',
                ' Max Packet Length': 'Max Packet Length',
                ' Packet Length Mean': 'Packet Length Mean',
                ' Packet Length Std': 'Packet Length Std',
                ' Packet Length Variance': 'Packet Length Variance',
                ' Average Packet Size': 'Average Packet Size',
                ' Avg Bwd Segment Size': 'Avg Bwd Segment Size',
                ' Subflow Bwd Bytes': 'Subflow Bwd Bytes',
                ' Init_Win_bytes_forward': 'Init_Win_bytes_forward',
                ' min_seg_size_forward': 'min_seg_size_forward'
            }

            # Rename the columns according to the mapping
            input_df.rename(columns=mapping, inplace=True)

            # List of required columns after renaming
            required_columns = [
                'Destination Port', 'Flow Duration', 'Total Length of Fwd Packets', 
                'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Mean', 
                'Bwd Packet Length Max', 'Bwd Packet Length Mean', 'Flow Bytes/s', 
                'Fwd Header Length', 'Bwd Header Length', 'Max Packet Length', 
                'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 
                'Average Packet Size', 'Avg Bwd Segment Size', 'Subflow Bwd Bytes', 
                'Init_Win_bytes_forward', 'min_seg_size_forward'
            ]

            # Check if the DataFrame contains the required columns
            if all(column in input_df.columns for column in required_columns):
                # Predict button
                if st.button("Predict"):
                    prediction = predict(input_df[required_columns])
                    st.success(f"The predicted label is: {prediction[0]}")
            else:
                st.error("The uploaded CSV does not contain all the required columns.")
        
        # For PCAP files, you need to implement a method to extract features from PCAP to a DataFrame
        # This requires additional libraries and logic, which is quite complex and environment-dependent
def main():
    st.sidebar.title("Navigation")
    app_mode = st.sidebar.radio("Choose one:", ["Manual Data Input", "CSV/PCAP Upload"])

    if app_mode == "Manual Data Input":
        show_form_page()
    elif app_mode == "CSV/PCAP Upload":
        show_file_upload_page()

if __name__ == "__main__":
    main()

    