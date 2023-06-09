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

interface IaeWETHInterface extends ethers.utils.Interface {
  functions: {
    'bridgeBurn(address,uint256)': FunctionFragment
    'bridgeMint(address,uint256)': FunctionFragment
    'deposit()': FunctionFragment
    'l1Address()': FunctionFragment
    'transferToGateway(address,uint256)': FunctionFragment
    'withdraw(uint256)': FunctionFragment
  }

  encodeFunctionData(
    functionFragment: 'bridgeBurn',
    values: [string, BigNumberish]
  ): string
  encodeFunctionData(
    functionFragment: 'bridgeMint',
    values: [string, BigNumberish]
  ): string
  encodeFunctionData(functionFragment: 'deposit', values?: undefined): string
  encodeFunctionData(functionFragment: 'l1Address', values?: undefined): string
  encodeFunctionData(
    functionFragment: 'transferToGateway',
    values: [string, BigNumberish]
  ): string
  encodeFunctionData(
    functionFragment: 'withdraw',
    values: [BigNumberish]
  ): string

  decodeFunctionResult(functionFragment: 'bridgeBurn', data: BytesLike): Result
  decodeFunctionResult(functionFragment: 'bridgeMint', data: BytesLike): Result
  decodeFunctionResult(functionFragment: 'deposit', data: BytesLike): Result
  decodeFunctionResult(functionFragment: 'l1Address', data: BytesLike): Result
  decodeFunctionResult(
    functionFragment: 'transferToGateway',
    data: BytesLike
  ): Result
  decodeFunctionResult(functionFragment: 'withdraw', data: BytesLike): Result

  events: {}
}

export class IaeWETH extends Contract {
  connect(signerOrProvider: Signer | Provider | string): this
  attach(addressOrName: string): this
  deployed(): Promise<this>

  on(event: EventFilter | string, listener: Listener): this
  once(event: EventFilter | string, listener: Listener): this
  addListener(eventName: EventFilter | string, listener: Listener): this
  removeAllListeners(eventName: EventFilter | string): this
  removeListener(eventName: any, listener: Listener): this

  interface: IaeWETHInterface

  functions: {
    bridgeBurn(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    'bridgeBurn(address,uint256)'(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    bridgeMint(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    'bridgeMint(address,uint256)'(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    deposit(overrides?: PayableOverrides): Promise<ContractTransaction>

    'deposit()'(overrides?: PayableOverrides): Promise<ContractTransaction>

    l1Address(overrides?: CallOverrides): Promise<[string]>

    'l1Address()'(overrides?: CallOverrides): Promise<[string]>

    transferToGateway(
      _from: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    'transferToGateway(address,uint256)'(
      _from: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    withdraw(
      _amount: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    'withdraw(uint256)'(
      _amount: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>
  }

  bridgeBurn(
    account: string,
    amount: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  'bridgeBurn(address,uint256)'(
    account: string,
    amount: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  bridgeMint(
    account: string,
    amount: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  'bridgeMint(address,uint256)'(
    account: string,
    amount: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  deposit(overrides?: PayableOverrides): Promise<ContractTransaction>

  'deposit()'(overrides?: PayableOverrides): Promise<ContractTransaction>

  l1Address(overrides?: CallOverrides): Promise<string>

  'l1Address()'(overrides?: CallOverrides): Promise<string>

  transferToGateway(
    _from: string,
    amount: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  'transferToGateway(address,uint256)'(
    _from: string,
    amount: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  withdraw(
    _amount: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  'withdraw(uint256)'(
    _amount: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  callStatic: {
    bridgeBurn(
      account: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<void>

    'bridgeBurn(address,uint256)'(
      account: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<void>

    bridgeMint(
      account: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<void>

    'bridgeMint(address,uint256)'(
      account: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<void>

    deposit(overrides?: CallOverrides): Promise<void>

    'deposit()'(overrides?: CallOverrides): Promise<void>

    l1Address(overrides?: CallOverrides): Promise<string>

    'l1Address()'(overrides?: CallOverrides): Promise<string>

    transferToGateway(
      _from: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<void>

    'transferToGateway(address,uint256)'(
      _from: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<void>

    withdraw(_amount: BigNumberish, overrides?: CallOverrides): Promise<void>

    'withdraw(uint256)'(
      _amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<void>
  }

  filters: {}

  estimateGas: {
    bridgeBurn(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>

    'bridgeBurn(address,uint256)'(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>

    bridgeMint(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>

    'bridgeMint(address,uint256)'(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>

    deposit(overrides?: PayableOverrides): Promise<BigNumber>

    'deposit()'(overrides?: PayableOverrides): Promise<BigNumber>

    l1Address(overrides?: CallOverrides): Promise<BigNumber>

    'l1Address()'(overrides?: CallOverrides): Promise<BigNumber>

    transferToGateway(
      _from: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>

    'transferToGateway(address,uint256)'(
      _from: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>

    withdraw(_amount: BigNumberish, overrides?: Overrides): Promise<BigNumber>

    'withdraw(uint256)'(
      _amount: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>
  }

  populateTransaction: {
    bridgeBurn(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    'bridgeBurn(address,uint256)'(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    bridgeMint(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    'bridgeMint(address,uint256)'(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    deposit(overrides?: PayableOverrides): Promise<PopulatedTransaction>

    'deposit()'(overrides?: PayableOverrides): Promise<PopulatedTransaction>

    l1Address(overrides?: CallOverrides): Promise<PopulatedTransaction>

    'l1Address()'(overrides?: CallOverrides): Promise<PopulatedTransaction>

    transferToGateway(
      _from: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    'transferToGateway(address,uint256)'(
      _from: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    withdraw(
      _amount: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    'withdraw(uint256)'(
      _amount: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>
  }
}
