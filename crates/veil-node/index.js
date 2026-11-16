const { existsSync, readdirSync } = require('fs')
const { join } = require('path')

const { platform, arch } = process

let nativeBinding = null

function isMusl() {
  if (!process.report || typeof process.report.getReport !== 'function') {
    try {
      const lddPath = require('child_process').execSync('which ldd').toString().trim()
      return require('fs').readFileSync(lddPath, 'utf8').includes('musl')
    } catch {
      return false
    }
  }
  const { glibcVersionRuntime } = process.report.getReport().header
  return !glibcVersionRuntime
}

switch (platform) {
  case 'linux':
    switch (arch) {
      case 'x64':
        if (isMusl()) {
          if (existsSync(join(__dirname, 'pii-veil-node.linux-x64-musl.node'))) {
            nativeBinding = require('./pii-veil-node.linux-x64-musl.node')
          }
        } else {
          if (existsSync(join(__dirname, 'pii-veil-node.linux-x64-gnu.node'))) {
            nativeBinding = require('./pii-veil-node.linux-x64-gnu.node')
          }
        }
        break
      case 'arm64':
        if (existsSync(join(__dirname, 'pii-veil-node.linux-arm64-gnu.node'))) {
          nativeBinding = require('./pii-veil-node.linux-arm64-gnu.node')
        }
        break
    }
    break
  case 'darwin':
    switch (arch) {
      case 'x64':
        if (existsSync(join(__dirname, 'pii-veil-node.darwin-x64.node'))) {
          nativeBinding = require('./pii-veil-node.darwin-x64.node')
        }
        break
      case 'arm64':
        if (existsSync(join(__dirname, 'pii-veil-node.darwin-arm64.node'))) {
          nativeBinding = require('./pii-veil-node.darwin-arm64.node')
        }
        break
    }
    break
  case 'win32':
    switch (arch) {
      case 'x64':
        if (existsSync(join(__dirname, 'pii-veil-node.win32-x64-msvc.node'))) {
          nativeBinding = require('./pii-veil-node.win32-x64-msvc.node')
        }
        break
    }
    break
}

if (!nativeBinding) {
  try {
    nativeBinding = require('./pii-veil-node.node')
  } catch {
    try {
      nativeBinding = require('./index.node')
    } catch {
      const files = readdirSync(__dirname).filter((f) => f.endsWith('.node'))
      if (files.length > 0) {
        nativeBinding = require(join(__dirname, files[0]))
      } else {
        throw new Error(
          `Failed to load native binding for pii-veil-node (${platform}-${arch}). Please ensure prebuilt binaries are available.`
        )
      }
    }
  }
}

module.exports = nativeBinding
