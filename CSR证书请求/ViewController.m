//
//  ViewController.m
//  CSR证书请求
//
//  Created by 刘成利 on 2017/6/21.
//  Copyright © 2017年 刘成利. All rights reserved.
//

#import "ViewController.h"

#import "pkcs10header.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
   
    
    
    
    /* 生成pkcs10 证书请求  格式：/CN=参数1/O=参数2/OU=参数3……
     * 例如："/CN=www.cicc.com/O=cicc.com/OU=IT/ST=Beijing City/L=beijing/C=CN/emailAddress=934800996@qq.com"
     * CN: 通用名称，域名  Common Name
     * O:  组织          Organization
     * OU: 部门          Organizational Unit
     * ST:  省份          State
     * L:  城市          Locality
     * C:  国家          Country
     */
    
    
    NSString *info =@"/CN=www.cicc.com/O=LiuChengli/OU=IT/ST=Beijing City/L=beijing/C=CN/emailAddress=934800996@qq.com";
    
    char chDN[255] ;
    memcpy(chDN, [info cStringUsingEncoding:NSASCIIStringEncoding], 2*[info length]);
    
    char chCSR[2048] = {0};
    char privateKey[2048] = {0};
    
    
    long int rv = GenCSR(chDN, strlen(chDN), chCSR, sizeof(chCSR),privateKey);
    
    
    NSString* pkcs10=[NSString stringWithFormat:@"%s",chCSR];
    NSString* priKey=[NSString stringWithFormat:@"%s",privateKey];
    

    // 返回的数组的第一个为PKCS10 CSR证书请求，第二个值为（未加密的）私钥

    
    NSLog(@"CSR:\n %@ \n PrivateKey:\n%@ \n",pkcs10,priKey);

    
    
    
    
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
