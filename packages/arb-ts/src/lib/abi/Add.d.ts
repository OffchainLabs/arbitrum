/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import {
  ethers,
  EventFilter,
  Signer,
  BigNumber,
  BigNumberish,
  PopulatedTransaction,
} from 'ethers'
import {
  Contract,
  ContractTransaction,
  Overrides,
  PayableOverrides,
  CallOverrides,
} from '@ethersproject/contracts'
import { BytesLike } from '@ethersproject/bytes'
import { Listener, Provider } from '@ethersproject/providers'
import { FunctionFragment, EventFragment, Result } from '@ethersproject/abi'

interface AddInterface extends ethers.utils.Interface {
  functions: {
    'add(uint256,uint256)': FunctionFragment
    'getSeqNum()': FunctionFragment
    'isNotTopLevel()': FunctionFragment
    'isTopLevel()': FunctionFragment
    'mult(uint256,uint256)': FunctionFragment
    'payTo(address)': FunctionFragment
    'pythag(uint256,uint256)': FunctionFragment
    'withdraw5000()': FunctionFragment
    'withdrawMyEth()': FunctionFragment
  }

  encodeFunctionData(
    functionFragment: 'add',
    values: [BigNumberish, BigNumberish]
  ): string
  encodeFunctionData(functionFragment: 'getSeqNum', values?: undefined): string
  encodeFunctionData(
    functionFragment: 'isNotTopLevel',
    values?: undefined
  ): string
  encodeFunctionData(functionFragment: 'isTopLevel', values?: undefined): string
  encodeFunctionData(
    functionFragment: 'mult',
    values: [BigNumberish, BigNumberish]
  ): string
  encodeFunctionData(functionFragment: 'payTo', values: [string]): string
  encodeFunctionData(
    functionFragment: 'pythag',
    values: [BigNumberish, BigNumberish]
  ): string
  encodeFunctionData(
    functionFragment: 'withdraw5000',
    values?: undefined
  ): string
  encodeFunctionData(
    functionFragment: 'withdrawMyEth',
    values?: undefined
  ): string

  decodeFunctionResult(functionFragment: 'add', data: BytesLike): Result
  decodeFunctionResult(functionFragment: 'getSeqNum', data: BytesLike): Result
  decodeFunctionResult(
    functionFragment: 'isNotTopLevel',
    data: BytesLike
  ): Result
  decodeFunctionResult(functionFragment: 'isTopLevel', data: BytesLike): Result
  decodeFunctionResult(functionFragment: 'mult', data: BytesLike): Result
  decodeFunctionResult(functionFragment: 'payTo', data: BytesLike): Result
  decodeFunctionResult(functionFragment: 'pythag', data: BytesLike): Result
  decodeFunctionResult(
    functionFragment: 'withdraw5000',
    data: BytesLike
  ): Result
  decodeFunctionResult(
    functionFragment: 'withdrawMyEth',
    data: BytesLike
  ): Result

  events: {}
}

export class Add extends Contract {
  connect(signerOrProvider: Signer | Provider | string): this
  attach(addressOrName: string): this
  deployed(): Promise<this>

  on(event: EventFilter | string, listener: Listener): this
  once(event: EventFilter | string, listener: Listener): this
  addListener(eventName: EventFilter | string, listener: Listener): this
  removeAllListeners(eventName: EventFilter | string): this
  removeListener(eventName: any, listener: Listener): this

  interface: AddInterface

  functions: {
    add(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<[BigNumber]>

    'add(uint256,uint256)'(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<[BigNumber]>

    getSeqNum(overrides?: CallOverrides): Promise<[BigNumber]>

    'getSeqNum()'(overrides?: CallOverrides): Promise<[BigNumber]>

    isNotTopLevel(overrides?: Overrides): Promise<ContractTransaction>

    'isNotTopLevel()'(overrides?: Overrides): Promise<ContractTransaction>

    isTopLevel(overrides?: Overrides): Promise<ContractTransaction>

    'isTopLevel()'(overrides?: Overrides): Promise<ContractTransaction>

    mult(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<[BigNumber]>

    'mult(uint256,uint256)'(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<[BigNumber]>

    payTo(
      addr: string,
      overrides?: PayableOverrides
    ): Promise<ContractTransaction>

    'payTo(address)'(
      addr: string,
      overrides?: PayableOverrides
    ): Promise<ContractTransaction>

    pythag(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<[BigNumber]>

    'pythag(uint256,uint256)'(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<[BigNumber]>

    withdraw5000(overrides?: Overrides): Promise<ContractTransaction>

    'withdraw5000()'(overrides?: Overrides): Promise<ContractTransaction>

    withdrawMyEth(overrides?: PayableOverrides): Promise<ContractTransaction>

    'withdrawMyEth()'(
      overrides?: PayableOverrides
    ): Promise<ContractTransaction>
  }

  add(
    x: BigNumberish,
    y: BigNumberish,
    overrides?: CallOverrides
  ): Promise<BigNumber>

  'add(uint256,uint256)'(
    x: BigNumberish,
    y: BigNumberish,
    overrides?: CallOverrides
  ): Promise<BigNumber>

  getSeqNum(overrides?: CallOverrides): Promise<BigNumber>

  'getSeqNum()'(overrides?: CallOverrides): Promise<BigNumber>

  isNotTopLevel(overrides?: Overrides): Promise<ContractTransaction>

  'isNotTopLevel()'(overrides?: Overrides): Promise<ContractTransaction>

  isTopLevel(overrides?: Overrides): Promise<ContractTransaction>

  'isTopLevel()'(overrides?: Overrides): Promise<ContractTransaction>

  mult(
    x: BigNumberish,
    y: BigNumberish,
    overrides?: CallOverrides
  ): Promise<BigNumber>

  'mult(uint256,uint256)'(
    x: BigNumberish,
    y: BigNumberish,
    overrides?: CallOverrides
  ): Promise<BigNumber>

  payTo(
    addr: string,
    overrides?: PayableOverrides
  ): Promise<ContractTransaction>

  'payTo(address)'(
    addr: string,
    overrides?: PayableOverrides
  ): Promise<ContractTransaction>

  pythag(
    x: BigNumberish,
    y: BigNumberish,
    overrides?: CallOverrides
  ): Promise<BigNumber>

  'pythag(uint256,uint256)'(
    x: BigNumberish,
    y: BigNumberish,
    overrides?: CallOverrides
  ): Promise<BigNumber>

  withdraw5000(overrides?: Overrides): Promise<ContractTransaction>

  'withdraw5000()'(overrides?: Overrides): Promise<ContractTransaction>

  withdrawMyEth(overrides?: PayableOverrides): Promise<ContractTransaction>

  'withdrawMyEth()'(overrides?: PayableOverrides): Promise<ContractTransaction>

  callStatic: {
    add(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<BigNumber>

    'add(uint256,uint256)'(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<BigNumber>

    getSeqNum(overrides?: CallOverrides): Promise<BigNumber>

    'getSeqNum()'(overrides?: CallOverrides): Promise<BigNumber>

    isNotTopLevel(overrides?: CallOverrides): Promise<boolean>

    'isNotTopLevel()'(overrides?: CallOverrides): Promise<boolean>

    isTopLevel(overrides?: CallOverrides): Promise<boolean>

    'isTopLevel()'(overrides?: CallOverrides): Promise<boolean>

    mult(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<BigNumber>

    'mult(uint256,uint256)'(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<BigNumber>

    payTo(addr: string, overrides?: CallOverrides): Promise<void>

    'payTo(address)'(addr: string, overrides?: CallOverrides): Promise<void>

    pythag(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<BigNumber>

    'pythag(uint256,uint256)'(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<BigNumber>

    withdraw5000(overrides?: CallOverrides): Promise<void>

    'withdraw5000()'(overrides?: CallOverrides): Promise<void>

    withdrawMyEth(overrides?: CallOverrides): Promise<void>

    'withdrawMyEth()'(overrides?: CallOverrides): Promise<void>
  }

  filters: {}

  estimateGas: {
    add(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<BigNumber>

    'add(uint256,uint256)'(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<BigNumber>

    getSeqNum(overrides?: CallOverrides): Promise<BigNumber>

    'getSeqNum()'(overrides?: CallOverrides): Promise<BigNumber>

    isNotTopLevel(overrides?: Overrides): Promise<BigNumber>

    'isNotTopLevel()'(overrides?: Overrides): Promise<BigNumber>

    isTopLevel(overrides?: Overrides): Promise<BigNumber>

    'isTopLevel()'(overrides?: Overrides): Promise<BigNumber>

    mult(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<BigNumber>

    'mult(uint256,uint256)'(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<BigNumber>

    payTo(addr: string, overrides?: PayableOverrides): Promise<BigNumber>

    'payTo(address)'(
      addr: string,
      overrides?: PayableOverrides
    ): Promise<BigNumber>

    pythag(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<BigNumber>

    'pythag(uint256,uint256)'(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<BigNumber>

    withdraw5000(overrides?: Overrides): Promise<BigNumber>

    'withdraw5000()'(overrides?: Overrides): Promise<BigNumber>

    withdrawMyEth(overrides?: PayableOverrides): Promise<BigNumber>

    'withdrawMyEth()'(overrides?: PayableOverrides): Promise<BigNumber>
  }

  populateTransaction: {
    add(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>

    'add(uint256,uint256)'(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>

    getSeqNum(overrides?: CallOverrides): Promise<PopulatedTransaction>

    'getSeqNum()'(overrides?: CallOverrides): Promise<PopulatedTransaction>

    isNotTopLevel(overrides?: Overrides): Promise<PopulatedTransaction>

    'isNotTopLevel()'(overrides?: Overrides): Promise<PopulatedTransaction>

    isTopLevel(overrides?: Overrides): Promise<PopulatedTransaction>

    'isTopLevel()'(overrides?: Overrides): Promise<PopulatedTransaction>

    mult(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>

    'mult(uint256,uint256)'(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>

    payTo(
      addr: string,
      overrides?: PayableOverrides
    ): Promise<PopulatedTransaction>

    'payTo(address)'(
      addr: string,
      overrides?: PayableOverrides
    ): Promise<PopulatedTransaction>

    pythag(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>

    'pythag(uint256,uint256)'(
      x: BigNumberish,
      y: BigNumberish,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>

    withdraw5000(overrides?: Overrides): Promise<PopulatedTransaction>

    'withdraw5000()'(overrides?: Overrides): Promise<PopulatedTransaction>

    withdrawMyEth(overrides?: PayableOverrides): Promise<PopulatedTransaction>

    'withdrawMyEth()'(
      overrides?: PayableOverrides
    ): Promise<PopulatedTransaction>
  }
}
