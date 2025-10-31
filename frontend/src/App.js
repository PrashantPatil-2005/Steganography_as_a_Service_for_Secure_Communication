import React, { useState, useId } from 'react';
import axios from 'axios';
import './App.css';

// Ensure API works even if dev proxy isn't active
axios.defaults.baseURL = process.env.NODE_ENV === 'development' ? 'http://localhost:5000' : '';
axios.defaults.withCredentials = false;
axios.defaults.timeout = 30000;

// Custom File Upload Component with Drag & Drop
const FileUpload = ({ onFileSelect, accept, required }) => {
  const [isDragOver, setIsDragOver] = useState(false);
  const inputId = useId();

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragOver(true);
  }; 

  const handleDragLeave = (e) => {
    e.preventDefault();
    setIsDragOver(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragOver(false);
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      onFileSelect(files[0]);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files.length > 0) {
      onFileSelect(e.target.files[0]);
    }
  };

  return (
    <div
      className={`file-upload ${isDragOver ? 'drag-over' : ''}`}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      <input
        type="file"
        accept={accept}
        onChange={handleFileChange}
        style={{ display: 'none' }}
        id={inputId}
      />
      <label htmlFor={inputId} className="file-upload-label">
        <div className="file-upload-content">
          <div className="file-upload-icon">📁</div>
          <div className="file-upload-text">
            <strong>Drop your image here</strong>
            <span>or click to browse</span>
          </div>
        </div>
      </label>
    </div>
  );
};

function App() {
  const [activeTab, setActiveTab] = useState('embed');
  const [file, setFile] = useState(null);
  const [message, setMessage] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [messageId, setMessageId] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleEmbed = async (e) => {
    e.preventDefault();
    console.log('[embed] submit clicked', { hasFile: !!file, hasMessage: !!message, hasPass: !!passphrase });
    if (!file || !message || !passphrase) {
      setError('Please fill in all fields');
      return;
    }

    setLoading(true);
    setError(null);

    const formData = new FormData();
    formData.append('file', file, file.name);
    formData.append('message', message);
    formData.append('passphrase', passphrase);

    try {
      const response = await axios.post('/api/stego/embed', formData);
      setResult(response.data);
      // Auto download the generated image
      const downloadPath = response.data?.download_path;
      const suggestedName = response.data?.stego_filename || 'stego.png';
      if (downloadPath) {
        try {
          const fileResp = await axios.get(downloadPath, { responseType: 'blob' });
          const blobUrl = URL.createObjectURL(new Blob([fileResp.data]));
          const link = document.createElement('a');
          link.href = blobUrl;
          link.download = suggestedName;
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
          URL.revokeObjectURL(blobUrl);
        } catch (_) {
          // Fallback: open the download path
          window.location.href = downloadPath;
        }
      }
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const handleExtract = async (e) => {
    e.preventDefault();
    console.log('[extract] submit clicked', { hasFile: !!file, hasPass: !!passphrase, messageId });
    if (!file || !passphrase) {
      setError('Please select a file and enter passphrase');
      return;
    }

    setLoading(true);
    setError(null);

    const formData = new FormData();
    formData.append('file', file, file.name);
    formData.append('passphrase', passphrase);
    if (messageId) formData.append('message_id', messageId);

    try {
      const response = await axios.post('/api/stego/extract', formData);
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const handleAnalysis = async (e) => {
    e.preventDefault();
    console.log('[analysis] submit clicked', { hasFile: !!file });
    if (!file) {
      setError('Please select a file for analysis');
      return;
    }

    setLoading(true);
    setError(null);

    const formData = new FormData();
    formData.append('file', file, file.name);

    try {
      const response = await axios.post('/api/stego/analysis', formData);
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="App">
      <header className="App-header">
        <h1> Secure Steganography</h1>
        <p>Hide messages in plain sight with military-grade encryption</p>
      </header>

      <div className="container">
        <div className="tabs">
          <button
            className={activeTab === 'embed' ? 'active' : ''}
            onClick={() => setActiveTab('embed')}
          >
            <span> Hide Message</span>
          </button>
          <button
            className={activeTab === 'extract' ? 'active' : ''}
            onClick={() => setActiveTab('extract')}
          >
            <span> Reveal Message</span>
          </button>
          <button
            className={activeTab === 'analysis' ? 'active' : ''}
            onClick={() => setActiveTab('analysis')}
          >
            <span> Analyze Image</span>
          </button>
        </div>

        {error && <div className="error">{error}</div>}

        {activeTab === 'embed' && (
          <form onSubmit={handleEmbed} className="form">
            <h2> Encrypt & Hide Message</h2>
            <div className="form-group">
              <label> Cover Image</label>
              <FileUpload 
                onFileSelect={setFile}
                accept="image/*"
                required={true}
              />
            {file && (
              <div style={{ marginTop: '8px', fontSize: '12px', color: '#334155' }}>
                Selected: <code>{file.name}</code>
              </div>
            )}
            </div>
            <div className="form-group">
              <label>Secret Message</label>
              <textarea
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Type your confidential message here..."
                required
              />
            </div>
            <div className="form-group">
              <label>Encryption Key</label>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder="Create a strong passphrase for encryption"
                required
              />
            </div>
            <button type="submit" disabled={loading}>
              {loading ? ' Encrypting & Hiding...' : ' Hide Message'}
            </button>
          </form>
        )}

        {activeTab === 'extract' && (
          <form onSubmit={handleExtract} className="form">
            <h2> Decrypt & Reveal Message</h2>
            <div className="form-group">
              <label>📷 Stego Image</label>
              <FileUpload 
                onFileSelect={setFile}
                accept="image/*"
                required={true}
              />
            {file && (
              <div style={{ marginTop: '8px', fontSize: '12px', color: '#334155' }}>
                Selected: <code>{file.name}</code>
              </div>
            )}
            </div>
            <div className="form-group">
              <label> Decryption Key</label>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder="Enter the passphrase used for encryption"
                required
              />
            </div>
            <div className="form-group">
              <label>Message ID (Optional)</label>
              <input
                type="text"
                value={messageId}
                onChange={(e) => setMessageId(e.target.value)}
                placeholder="For tamper detection and verification"
              />
            </div>
            <button type="submit" disabled={loading}>
              {loading ? ' Decrypting...' : ' Extract Message'}
            </button>
          </form>
        )}

        {activeTab === 'analysis' && (
          <form onSubmit={handleAnalysis} className="form">
            <h2> Steganalysis Detection</h2>
            <div className="form-group">
              <label>Image to Analyze</label>
              <FileUpload 
                onFileSelect={setFile}
                accept="image/*"
                required={true}
              />
            {file && (
              <div style={{ marginTop: '8px', fontSize: '12px', color: '#334155' }}>
                Selected: <code>{file.name}</code>
              </div>
            )}
            </div>
            <button type="submit" disabled={loading}>
              {loading ? 'Analyzing...' : 'Detect Steganography'}
            </button>
          </form>
        )}

        {result && (
          <div className="result">
            {activeTab === 'embed' && result.message === 'Embedded successfully' && (
              <>
                <h3>✅ Message Successfully Hidden!</h3>
                <div style={{marginBottom: '20px'}}>
                  <p><strong> Message ID:</strong> <code>{result.message_id}</code></p>
                  <p><strong> File Hash:</strong> <code>{result.stego_hash}</code></p>
                </div>
                <div style={{marginBottom: '20px'}}>
                  <img
                    src={`/api/stego/preview/${result.message_id}`}
                    alt="Encrypted image preview"
                    style={{maxWidth: '100%', border: '2px solid #e0f2fe', borderRadius: 12, boxShadow: '0 4px 12px rgba(0,0,0,0.1)'}}
                    onError={(e) => { e.currentTarget.style.display = 'none'; }}
                  />
                </div>
                <div>
                  <a
                    href={result.download_path}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="download-link"
                  >
                    📥 Download Encrypted Image
                  </a>
                </div>
              </>
            )}

            {activeTab === 'extract' && result.data && (
              <>
                <h3> Message Successfully Extracted!</h3>
                <div className="form-group">
                  <label> Decrypted Message:</label>
                  <textarea 
                    readOnly 
                    value={result.data} 
                    style={{
                      width: '100%', 
                      minHeight: '120px',
                      background: '#f8fafc',
                      border: '2px solid #e2e8f0',
                      borderRadius: '12px',
                      padding: '16px',
                      fontFamily: 'inherit',
                      fontSize: '14px',
                      lineHeight: '1.5'
                    }} 
                  />
                </div>
              </>
            )}

            {activeTab === 'analysis' && (result.chi_square_score !== undefined) && (
              <>
                <h3> Steganalysis Complete</h3>
                <div style={{background: '#f8fafc', padding: '20px', borderRadius: '12px', border: '2px solid #e2e8f0'}}>
                  <p><strong> Chi-square Score:</strong> <code>{result.chi_square_score}</code></p>
                  <p style={{marginTop: '12px', fontSize: '14px', color: '#64748b'}}>
                    {result.chi_square_score > 0.05 ? 
                      ' No significant steganographic content detected' : 
                      ' Potential steganographic content detected'
                    }
                  </p>
                </div>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
