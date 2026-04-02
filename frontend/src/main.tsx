import React, { Component, ErrorInfo, ReactNode } from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'

interface EBProps { children: ReactNode }
interface EBState { hasError: boolean; error: Error | null }

class ErrorBoundary extends Component<EBProps, EBState> {
  constructor(props: EBProps) {
    super(props)
    this.state = { hasError: false, error: null }
  }
  static getDerivedStateFromError(error: Error): EBState {
    return { hasError: true, error }
  }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('CloudScan error:', error, info.componentStack)
  }
  render() {
    if (this.state.hasError) {
      return (
        <div style={{display:'flex',alignItems:'center',justifyContent:'center',minHeight:'100vh',background:'#0a0e1a',color:'#e0e0e0',fontFamily:'-apple-system,BlinkMacSystemFont,sans-serif'}}>
          <div style={{textAlign:'center',maxWidth:480,padding:40}}>
            <div style={{fontSize:48,marginBottom:16}}>&#9888;</div>
            <h1 style={{fontSize:24,fontWeight:700,marginBottom:8}}>Something went wrong</h1>
            <p style={{fontSize:14,color:'#8892a4',marginBottom:24}}>
              An unexpected error occurred. Please reload the page to continue.
            </p>
            <pre style={{background:'#141926',padding:16,borderRadius:8,fontSize:11,color:'#f04848',textAlign:'left',overflow:'auto',maxHeight:120,marginBottom:24}}>
              {this.state.error?.message}
            </pre>
            <button
              onClick={() => window.location.reload()}
              style={{background:'#00e5a0',color:'#000',border:'none',padding:'10px 24px',borderRadius:8,fontSize:14,fontWeight:600,cursor:'pointer'}}
            >
              Reload Page
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>,
)
