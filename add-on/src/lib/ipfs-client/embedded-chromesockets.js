'use strict'
/* eslint-env browser, webextensions */
const browser = require('webextension-polyfill')

const debug = require('debug')
const log = debug('ipfs-companion:client:embedded')
log.error = debug('ipfs-companion:client:embedded:error')

// Polyfills required by embedded HTTP server
const uptimeStart = Date.now()
process.uptime = () => Math.floor((Date.now() - uptimeStart) / 1000)
process.hrtime = require('browser-process-hrtime')

const mergeOptions = require('merge-options')
const Ipfs = require('ipfs')
const HttpApi = require('ipfs/src/http')
const multiaddr = require('multiaddr')
const maToUri = require('multiaddr-to-uri')

const { optionDefaults } = require('../options')

// js-ipfs with embedded hapi HTTP server
let node = null
let nodeHttpApi = null

exports.init = function init (opts) {
  log('init embedded:chromesockets')

  const defaultOpts = JSON.parse(optionDefaults.ipfsNodeConfig)

  defaultOpts.libp2p = {
    config: {
      dht: {
        // TODO: check if below is needed after js-ipfs is released with DHT disabled
        enabled: false
      }
    }
  }

  const userOpts = JSON.parse(opts.ipfsNodeConfig)
  const ipfsOpts = mergeOptions.call({ concatArrays: true }, defaultOpts, userOpts, { start: false })
  log('creating js-ipfs with opts: ', ipfsOpts)
  node = new Ipfs(ipfsOpts)

  return new Promise((resolve, reject) => {
    node.once('error', (error) => {
      log.error('something went terribly wrong during startup of js-ipfs!', error)
      reject(error)
    })
    node.once('ready', async () => {
      node.once('start', async () => {
        // HttpApi is off in browser context and needs to be started separately
        try {
          const httpServers = new HttpApi(node, ipfsOpts)
          nodeHttpApi = await httpServers.start()
          await updateConfigWithHttpEndpoints(node, opts)
          resolve(node)
        } catch (err) {
          reject(err)
        }
      })
      try {
        node.on('error', error => {
          log.error('something went terribly wrong in embedded js-ipfs!', error)
        })
        await node.start()
      } catch (err) {
        reject(err)
      }
    })
  })
}

const multiaddr2httpUrl = (ma) => maToUri(ma.includes('/http') ? ma : multiaddr(ma).encapsulate('/http'))

// Update internal configuration to HTTP Endpoints from js-ipfs instance
async function updateConfigWithHttpEndpoints (ipfs, opts) {
  const localConfig = await browser.storage.local.get('ipfsNodeConfig')
  if (localConfig && localConfig.ipfsNodeConfig) {
    const gwMa = await ipfs.config.get('Addresses.Gateway')
    const apiMa = await ipfs.config.get('Addresses.API')
    const httpGateway = multiaddr2httpUrl(gwMa)
    const httpApi = multiaddr2httpUrl(apiMa)
    // update ports in JSON configuration for embedded js-ipfs
    const ipfsNodeConfig = JSON.parse(localConfig.ipfsNodeConfig)
    ipfsNodeConfig.config.Addresses.Gateway = gwMa
    ipfsNodeConfig.config.Addresses.API = apiMa
    const configChanges = {
      customGatewayUrl: httpGateway,
      ipfsApiUrl: httpApi,
      ipfsNodeConfig: JSON.stringify(ipfsNodeConfig, null, 2)
    }
    // update current runtime config (in place, effective without restart)
    Object.assign(opts, configChanges)
    // update user config in storage (effective on next run)
    log(`synchronizing ipfsNodeConfig with customGatewayUrl (${configChanges.customGatewayUrl}) and ipfsApiUrl (${configChanges.ipfsApiUrl})`)
    await browser.storage.local.set(configChanges)
  }
}

exports.destroy = async function () {
  log('destroy: embedded:chromesockets')

  if (nodeHttpApi) {
    try {
      await nodeHttpApi.stop()
    } catch (err) {
      // TODO: needs upstream fix like https://github.com/ipfs/js-ipfs/issues/2257
      if (err.message !== 'Cannot stop server while in stopping phase') {
        log.error('failed to stop HttpApi', err)
      }
    }
    nodeHttpApi = null
  }
  if (node) {
    const stopped = new Promise((resolve, reject) => {
      node.on('stop', resolve)
      node.on('error', reject)
    })
    try {
      await node.stop()
    } catch (err) {
      // TODO: remove when fixed upstream: https://github.com/ipfs/js-ipfs/issues/2257
      if (err.message === 'Not able to stop from state: stopping') {
        log('destroy: embedded:chromesockets waiting for node.stop()')
        await stopped
      } else {
        throw err
      }
    }
    node = null
  }
}
